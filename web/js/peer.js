/**
 * Dead Drop — P2P Connection Layer
 *
 * Manages a single WebRTC peer connection with a data channel.
 * The signaling object must expose a `send(msg)` method.
 * Key exchange happens over the data channel (not the signaling server)
 * so the server never sees encryption keys.
 */

import { Handshake } from './handshake.js';
import { PROTOCOL_VERSION } from './crypto.js';

const MAX_DATA_CHANNEL_MESSAGE = 256 * 1024;
const REKEY_INTERVAL_MS = 10 * 60 * 1000; // DH ratchet every 10 min for forward secrecy
const REKEY_TIMEOUT_MS = 30 * 1000;
const HANDSHAKE_TIMEOUT_MS = 30 * 1000;   // fail an unfinished handshake instead of hanging forever

export class PeerConnection {
  /**
   * @param {Object}      signaling    – { send(msg) }
   * @param {CryptoLayer} cryptoLayer  – shared crypto instance
   * @param {Function}    onMessage    – called with each decrypted peer message
   * @param {Function}    onStateChange – called with 'connected' | 'encrypted' | 'disconnected'
   */
  constructor(signaling, cryptoLayer, onMessage, onStateChange, iceConfig = {}) {
    this.signaling = signaling;
    this.crypto = cryptoLayer;
    this.onMessage = onMessage;
    this.onStateChange = onStateChange;
    this.iceServers = Array.isArray(iceConfig.iceServers) ? iceConfig.iceServers : [];
    // relayOnly forces all traffic through the TURN relay so the peer never learns
    // our IP (and we never learn theirs) — at the cost of routing via the server.
    this.relayOnly = !!iceConfig.relayOnly;
    this.pc = null;
    this.dc = null;            // data channel
    this.remotePeerId = null;
    this.connected = false;
    this.onRemoteTrack = null; // callback for incoming remote media
    this.localStream = null;
    this.isInitiator = false;  // the data-channel creator drives rekeys
    this.handshake = null;
    this._rekeyTimer = null;
    this._rekeyTimeout = null;
    this._sendQ = Promise.resolve(); // keeps sealed sends in order
    this._recvQ = Promise.resolve(); // keeps opened messages in order
    // Media path authenticity: call audio/video is protected by DTLS-SRTP, whose
    // certificate is authenticated only by the fingerprint in the SDP — which is
    // relayed by the (untrusted) signaling server. Until we confirm, over the
    // SAS-verified data channel, that the peer's real DTLS cert matches what
    // signaling delivered, the media path is NOT trusted and calls are blocked.
    this.mediaVerified = false;
    this._fpTimer = null;
    this._handshakeTimer = null;
  }

  /* ── Initiator (caller) ── */

  async createOffer(remotePeerId) {
    this.remotePeerId = remotePeerId;
    this.isInitiator = true;
    this.pc = this._newRTCPeerConnection();

    // The initiator creates the data channel before the offer
    this.dc = this.pc.createDataChannel('deaddrop', { ordered: true });
    this._wireDataChannel(this.dc);

    const offer = await this.pc.createOffer();
    await this.pc.setLocalDescription(offer);

    this.signaling.send({
      type: 'offer',
      to: remotePeerId,
      payload: JSON.stringify(offer),
    });
  }

  /* ── Callee ── */

  async handleOffer(from, offer) {
    this.remotePeerId = from;
    this.isInitiator = false;
    this.pc = this._newRTCPeerConnection();

    // The callee waits for the data channel from the initiator
    this.pc.ondatachannel = (e) => {
      this.dc = e.channel;
      this._wireDataChannel(this.dc);
    };

    await this.pc.setRemoteDescription(new RTCSessionDescription(offer));
    const answer = await this.pc.createAnswer();
    await this.pc.setLocalDescription(answer);

    this.signaling.send({
      type: 'answer',
      to: from,
      payload: JSON.stringify(answer),
    });
  }

  async handleAnswer(answer) {
    if (this.pc) {
      await this.pc.setRemoteDescription(new RTCSessionDescription(answer));
    }
  }

  async handleIceCandidate(candidate) {
    if (this.pc) {
      await this.pc.addIceCandidate(new RTCIceCandidate(candidate));
    }
  }

  /**
   * Send an app-level JS object over the data channel. EVERY message is sealed
   * into an encrypted, replay-protected, length-padded envelope — typing
   * notices, read receipts, deletes and call signaling included — so even a
   * DTLS-terminating man-in-the-middle sees only uniform ciphertext blobs.
   * Sends are queued to preserve ordering across async encryption.
   */
  send(obj) {
    if (!this.dc || this.dc.readyState !== 'open') {
      throw new Error('Data channel not open');
    }
    return this._queueSealed(obj);
  }

  /* ── Media (audio / video calls) ── */

  /**
   * Add local media and create a renegotiation offer.
   * Called by the call initiator after the remote peer accepts.
   */
  async startMedia(stream) {
    this.localStream = stream;
    for (const track of stream.getTracks()) this.pc.addTrack(track, stream);
    const offer = await this.pc.createOffer();
    await this.pc.setLocalDescription(offer);
    return this.pc.localDescription;
  }

  /**
   * Handle a renegotiation offer from the remote peer.
   * Adds local tracks (if provided) and returns an SDP answer.
   */
  async acceptMedia(offer, localStream) {
    await this.pc.setRemoteDescription(new RTCSessionDescription(offer));
    if (localStream) {
      this.localStream = localStream;
      for (const track of localStream.getTracks()) this.pc.addTrack(track, localStream);
    }
    const answer = await this.pc.createAnswer();
    await this.pc.setLocalDescription(answer);
    return this.pc.localDescription;
  }

  /** Handle the renegotiation answer. */
  async completeMedia(answer) {
    await this.pc.setRemoteDescription(new RTCSessionDescription(answer));
  }

  /** Stop local media and remove tracks from the connection. */
  stopMedia() {
    if (this.localStream) {
      for (const track of this.localStream.getTracks()) track.stop();
      this.localStream = null;
    }
    if (this.pc) {
      for (const sender of this.pc.getSenders()) {
        if (sender.track) { try { this.pc.removeTrack(sender); } catch (_) { /* */ } }
      }
    }
  }

  close() {
    this._clearRekey();
    clearTimeout(this._fpTimer);
    clearTimeout(this._handshakeTimer);
    this.handshake = null;
    this.stopMedia();
    if (this.dc) this.dc.close();
    if (this.pc) this.pc.close();
    this.connected = false;
    this.onStateChange('disconnected');
  }

  /* ── Private ── */

  _newRTCPeerConnection() {
    // ICE servers come from the server's /api/turn (self-hosted coturn) — no
    // third-party STUN, so peer IPs are never disclosed to Google et al.
    const pc = new RTCPeerConnection({
      iceServers: this.iceServers,
      iceTransportPolicy: this.relayOnly ? 'relay' : 'all',
    });

    pc.onicecandidate = (e) => {
      if (e.candidate) {
        this.signaling.send({
          type: 'ice-candidate',
          to: this.remotePeerId,
          payload: JSON.stringify(e.candidate),
        });
      }
    };

    // Incoming remote media tracks (audio/video calls)
    pc.ontrack = (e) => {
      if (this.onRemoteTrack) {
        this.onRemoteTrack(e.streams[0] || new MediaStream([e.track]));
      }
    };

    pc.onconnectionstatechange = () => {
      const s = pc.connectionState;
      if (s === 'connected') {
        this.connected = true;
        this.onStateChange('connected');
      } else if (s === 'disconnected' || s === 'failed' || s === 'closed') {
        this.connected = false;
        this.onStateChange('disconnected');
      }
    };

    return pc;
  }

  _wireDataChannel(ch) {
    ch.onopen = async () => {
      // Authenticated key exchange (commit-reveal) over the data channel.
      this.handshake = new Handshake(this.crypto, (m) => this._dcSend(m), {
        onEstablished: (sas) => this._onEstablished(sas),
        onError: (reason) => {
          console.warn('[peer] handshake failed:', reason);
          this.onStateChange('insecure', reason);
          this.close();
        },
      });
      // Don't let a peer (or relay) that opens the channel but stalls the key
      // exchange leave us stuck "exchanging keys" forever — fail it after a bound.
      this._handshakeTimer = setTimeout(() => {
        if (!this.crypto.established) {
          console.warn('[peer] handshake did not complete in time — closing');
          this.close();
        }
      }, HANDSHAKE_TIMEOUT_MS);
      try {
        await this.handshake.start();
      } catch (err) {
        console.warn('[peer] handshake start failed:', err);
      }
    };

    ch.onmessage = async (e) => {
      if (typeof e.data !== 'string' || e.data.length > MAX_DATA_CHANNEL_MESSAGE) {
        console.warn('[peer] Received invalid message size — ignoring');
        return;
      }
      let msg;
      try {
        msg = JSON.parse(e.data);
      } catch {
        console.warn('[peer] Received malformed message — ignoring');
        return;
      }
      if (!msg || typeof msg.type !== 'string') return;

      // The commit/reveal exchange is the only post-open plaintext protocol.
      if (msg.type.startsWith('kex-')) {
        if (this.handshake) {
          try { await this.handshake.handle(msg); } catch (err) { console.warn('[peer] kex error', err); }
        }
        return;
      }

      // Rekeys and app traffic arrive only in protocol-v4 sealed envelopes.
      if (msg.type !== 'enc' || msg.v !== PROTOCOL_VERSION) {
        console.warn('[peer] dropping unsealed app message');
        return;
      }
      if (!this.crypto.established) {
        console.warn('[peer] dropping pre-handshake app message');
        return;
      }
      this._recvQ = this._recvQ
        .then(async () => {
          const inner = await this.crypto.open(msg.c, msg.iv, msg.e);
          if (!inner || typeof inner.type !== 'string') return;
          if (inner.type === 'rekey-offer') { await this._onRekeyOffer(inner); return; }
          if (inner.type === 'rekey-answer') { await this._onRekeyAnswer(inner); return; }
          if (inner.type === 'dtls-fp') { this._onPeerFingerprint(inner); return; }
          this.onMessage(inner);
        })
        .catch((err) => console.warn('[peer] failed to open sealed message', err));
      await this._recvQ;
    };

    ch.onclose = () => {
      this.connected = false;
      this._clearRekey();
      this.onStateChange('disconnected');
    };
  }

  _dcSend(obj) {
    if (this.dc && this.dc.readyState === 'open') this.dc.send(JSON.stringify(obj));
  }

  _queueSealed(obj, epoch) {
    const operation = this._sendQ.then(() => this._sendSealedNow(obj, epoch));
    // Keep the queue usable after one failed operation while returning the real
    // failure to the caller that initiated it.
    this._sendQ = operation.catch((err) => {
      console.warn('[peer] sealed send failed', err);
    });
    return operation;
  }

  async _sendSealedNow(obj, epoch = this.crypto.sendEpoch) {
    if (!this.dc || this.dc.readyState !== 'open') throw new Error('Data channel not open');
    const { ciphertext, iv, epoch: usedEpoch } = await this.crypto.seal(obj, epoch);
    if (!this.dc || this.dc.readyState !== 'open') throw new Error('Data channel closed');
    this.dc.send(JSON.stringify({
      type: 'enc',
      v: PROTOCOL_VERSION,
      c: ciphertext,
      iv,
      e: usedEpoch,
    }));
  }

  _onEstablished(sas) {
    clearTimeout(this._handshakeTimer);
    this.onStateChange('encrypted', sas);
    if (this.isInitiator) this._scheduleRekey();
    // Bind the DTLS/media path to this cryptographic session. Human SAS
    // comparison is still required before the application may trust the peer.
    // Send our real local fingerprint over the encrypted channel so the peer
    // can check it against the fingerprint signaling handed them. Messages are
    // already safe (encrypted with the SAS key); this closes the call/media gap.
    this._verifyMediaPath();
  }

  /* ── Media-path (DTLS) authentication over the SAS-verified channel ── */

  _verifyMediaPath() {
    let mine;
    try {
      mine = extractFingerprints(this.pc?.localDescription?.sdp || '');
    } catch {
      mine = [];
    }
    if (mine.length === 0) return; // nothing to attest; calls stay disabled
    this._queueSealed({ type: 'dtls-fp', v: PROTOCOL_VERSION, fp: mine }).catch(() => {});
    // If the peer never confirms (old client, or a MitM dropping the message),
    // leave mediaVerified false — messaging still works, calls stay disabled.
    clearTimeout(this._fpTimer);
    this._fpTimer = setTimeout(() => {
      if (!this.mediaVerified) console.warn('[peer] media path unverified — calls disabled');
    }, 10000);
  }

  _onPeerFingerprint(msg) {
    clearTimeout(this._fpTimer);
    const theirs = Array.isArray(msg.fp)
      ? [...new Set(msg.fp.map((f) => String(f).toLowerCase()))]
      : [];
    let expected = [];
    try {
      expected = extractFingerprints(this.pc?.remoteDescription?.sdp || '');
    } catch { /* leave empty */ }
    if (expected.length === 0 || theirs.length === 0) {
      // Can't compare (unexpected) — don't tear down, but don't trust media either.
      console.warn('[peer] could not compare DTLS fingerprints — calls disabled');
      return;
    }
    if (fingerprintsMatch(expected, theirs)) {
      // The cert the peer actually holds matches what signaling delivered: no
      // DTLS man-in-the-middle. Media (calls) is now bound to the verified SAS.
      this.mediaVerified = true;
      this.onStateChange('media-verified');
    } else {
      // The peer's real DTLS cert differs from the SDP signaling relayed — a
      // man-in-the-middle is terminating the transport and could intercept a
      // call. Messages stayed confidential, but abort loudly.
      console.warn('[peer] DTLS fingerprint mismatch — media-path MITM');
      this.onStateChange('insecure', 'DTLS fingerprint mismatch — media path may be intercepted');
      this.close();
    }
  }

  /* ── DH ratchet (forward secrecy) — only the initiator drives the schedule ── */

  _scheduleRekey() {
    clearTimeout(this._rekeyTimer);
    this._rekeyTimer = setTimeout(() => this._doRekey(), REKEY_INTERVAL_MS);
  }

  _clearRekey() {
    if (this._rekeyTimer) { clearTimeout(this._rekeyTimer); this._rekeyTimer = null; }
    if (this._rekeyTimeout) { clearTimeout(this._rekeyTimeout); this._rekeyTimeout = null; }
  }

  async _doRekey() {
    if (!this.crypto.established || !this.dc || this.dc.readyState !== 'open') return;
    const operation = this._sendQ.then(async () => {
      const oldEpoch = this.crypto.sendEpoch;
      const offer = await this.crypto.beginRekey();
      await this._sendSealedNow({
        type: 'rekey-offer',
        v: PROTOCOL_VERSION,
        epoch: offer.epoch,
        publicKey: offer.publicKey,
      }, oldEpoch);
      clearTimeout(this._rekeyTimeout);
      this._rekeyTimeout = setTimeout(() => {
        console.warn('[peer] authenticated rekey timed out');
        this.onStateChange('insecure', 'rekey timed out');
        this.close();
      }, REKEY_TIMEOUT_MS);
    });
    this._sendQ = operation.catch((err) => {
      console.warn('[peer] rekey offer failed', err);
      this.onStateChange('insecure', 'rekey failed');
      this.close();
    });
    await operation.catch(() => {});
  }

  _onRekeyOffer(msg) {
    if (!this.crypto.established
        || msg.v !== PROTOCOL_VERSION
        || typeof msg.publicKey !== 'string'
        || !Number.isSafeInteger(msg.epoch)) {
      return Promise.reject(new Error('Malformed authenticated rekey offer'));
    }
    const operation = this._sendQ.then(async () => {
      const oldEpoch = this.crypto.sendEpoch;
      const answer = await this.crypto.acceptRekey(msg.publicKey, msg.epoch);
      // The answer must be authenticated under the old epoch. The initiator has
      // not installed the new receiving keys until this answer verifies.
      await this._sendSealedNow({
        type: 'rekey-answer',
        v: PROTOCOL_VERSION,
        epoch: answer.epoch,
        publicKey: answer.publicKey,
      }, oldEpoch);
    });
    this._sendQ = operation.catch((err) => {
      console.warn('[peer] rekey accept failed — tearing down to avoid key divergence', err);
      this.onStateChange('insecure', 'rekey failed');
      this.close();
    });
    return operation;
  }

  _onRekeyAnswer(msg) {
    if (msg.v !== PROTOCOL_VERSION
        || typeof msg.publicKey !== 'string'
        || !Number.isSafeInteger(msg.epoch)) {
      return Promise.reject(new Error('Malformed authenticated rekey answer'));
    }
    const operation = this._sendQ.then(async () => {
      await this.crypto.completeRekey(msg.publicKey, msg.epoch);
      clearTimeout(this._rekeyTimeout);
      this._rekeyTimeout = null;
      this._scheduleRekey(); // line up the next ratchet
    });
    this._sendQ = operation.catch((err) => {
      console.warn('[peer] rekey complete failed — tearing down to avoid key divergence', err);
      this.onStateChange('insecure', 'rekey failed');
      this.close();
    });
    return operation;
  }
}

/**
 * Pull the DTLS certificate fingerprint(s) out of an SDP blob. Every WebRTC SDP
 * carries `a=fingerprint:<alg> <hex:hex:…>` for the DTLS handshake that secures
 * both the data channel and any media. Returns a normalized, de-duplicated list.
 */
export function extractFingerprints(sdp) {
  const out = [];
  const lengths = new Map([['sha-256', 32], ['sha-384', 48], ['sha-512', 64]]);
  const re = /^a=fingerprint:(\S+)\s+(\S+)\s*$/gim;
  let m;
  while ((m = re.exec(sdp)) !== null) {
    const algorithm = m[1].toLowerCase();
    const octets = m[2].toLowerCase().split(':');
    if (octets.length !== lengths.get(algorithm)
        || !octets.every((octet) => /^[0-9a-f]{2}$/.test(octet))) continue;
    out.push(`${algorithm} ${octets.join(':')}`);
  }
  return [...new Set(out)];
}

/** Exact set comparison: an attacker cannot smuggle one genuine fingerprint
 * beside an attacker-controlled certificate and pass an overlap-only check. */
export function fingerprintsMatch(expected, asserted) {
  if (!Array.isArray(expected) || !Array.isArray(asserted)
      || expected.length === 0 || asserted.length === 0) return false;
  const a = [...new Set(expected.map((f) => String(f).toLowerCase()))].sort();
  const b = [...new Set(asserted.map((f) => String(f).toLowerCase()))].sort();
  return a.length === b.length && a.every((value, i) => value === b[i]);
}
