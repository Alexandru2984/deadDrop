/**
 * Dead Drop — P2P Connection Layer
 *
 * Manages a single WebRTC peer connection with a data channel.
 * The signaling object must expose a `send(msg)` method.
 * Key exchange happens over the data channel (not the signaling API), so the
 * intended protocol does not transmit application encryption keys to the server.
 */

import { bufToB64, b64ToBuf } from './util.js';
import { Handshake } from './handshake.js';
import { PROTOCOL_VERSION } from './crypto.js';
import { signTranscript, verifyTranscript, fingerprint } from './identity.js';

const MAX_DATA_CHANNEL_MESSAGE = 256 * 1024;
const REKEY_INTERVAL_MS = 10 * 60 * 1000; // periodic DH key evolution
const REKEY_TIMEOUT_MS = 30 * 1000;
const HANDSHAKE_TIMEOUT_MS = 30 * 1000;   // fail an unfinished handshake instead of hanging forever
const TRAFFIC_WINDOW_MS = 10 * 1000;
const MAX_MESSAGES_PER_WINDOW = 1500; // accommodates a complete 25 MB file
const MAX_BYTES_PER_WINDOW = 128 * 1024 * 1024;

export class PeerConnection {
  /**
   * @param {Object}      signaling    – { send(msg) }
   * @param {CryptoLayer} cryptoLayer  – shared crypto instance
   * @param {Function}    onMessage    – called with each decrypted peer message
   * @param {Function}    onStateChange – called with 'connected' | 'encrypted' | 'disconnected'
   */
  constructor(signaling, cryptoLayer, onMessage, onStateChange, iceConfig = {}, identity = null) {
    this.signaling = signaling;
    this.crypto = cryptoLayer;
    this.onMessage = onMessage;
    this.onStateChange = onStateChange;
    this.iceServers = Array.isArray(iceConfig.iceServers) ? iceConfig.iceServers : [];
    // relayOnly exposes TURN relay candidates to the peer instead of endpoint
    // addresses. The TURN/VPS operator still sees both endpoints and timing.
    this.relayOnly = !!iceConfig.relayOnly;
    this.pc = null;
    this.dc = null;            // data channel
    this.remotePeerId = null;
    this.connected = false;
    this.localVerified = false;
    this.remoteVerified = false;
    this.userVerified = false; // true only after both users confirm SAS/QR
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
    // relayed by the (untrusted) signaling server. We bind that fingerprint to
    // the encrypted session, then separately require both users to compare and
    // confirm the SAS before any call or application traffic is allowed.
    this.mediaVerified = false;
    // The exact certificate the peer attested. Every later renegotiation has to
    // still be that certificate, or the media path is no longer the one bound.
    this.boundFingerprints = null;
    // Opt-in saved contacts. `identity` is this browser's long-term keypair when
    // the user enabled the feature; peerIdentityFp is set only once the peer has
    // proved possession of the key it presented.
    this.identity = identity;
    this.peerIdentityFp = null;
    this._fpTimer = null;
    this._handshakeTimer = null;
    this._closed = false;
    this._trafficWindowAt = Date.now();
    this._trafficMessages = 0;
    this._trafficBytes = 0;
  }

  /* ── Initiator (caller) ── */

  async createOffer(remotePeerId) {
    if (this.pc || this._closed) throw new Error('Peer connection already initialized');
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
    if (this.pc || this._closed) throw new Error('Duplicate or late WebRTC offer');
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
   * notices, read receipts, deletes and call signaling included. Padding hides
   * exact length within a bucket, but not timing, counts, or bucket changes.
   * Sends are queued to preserve ordering across async encryption.
   */
  send(obj) {
    if (!this.dc || this.dc.readyState !== 'open') {
      throw new Error('Data channel not open');
    }
    if (!this.userVerified) {
      throw new Error('Peer identity has not been verified');
    }
    return this._queueSealed(obj);
  }

  /** Unlock app traffic only after the user confirms the out-of-band SAS. */
  markVerified() {
    if (!this.crypto.established) throw new Error('Encryption is not established');
    this.localVerified = true;
    const sent = this._queueSealed({ type: 'verify-ready', v: PROTOCOL_VERSION });
    this._updateVerificationState();
    return sent;
  }

  /** A mismatching QR/SAS is a terminal authentication failure. */
  rejectVerification(reason = 'safety code mismatch') {
    this.userVerified = false;
    this.localVerified = false;
    this.remoteVerified = false;
    this._terminateInsecure(reason);
  }

  /* ── Media (audio / video calls) ── */

  /**
   * Add local media and create a renegotiation offer.
   * Called by the call initiator after the remote peer accepts.
   */
  async startMedia(stream) {
    this._requireVerifiedMedia();
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
    this._requireVerifiedMedia();
    this._requireBoundCertificate(offer);
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
    this._requireVerifiedMedia();
    this._requireBoundCertificate(answer);
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

  close(notify = true) {
    if (this._closed) return;
    this._closed = true;
    this._clearRekey();
    clearTimeout(this._fpTimer);
    clearTimeout(this._handshakeTimer);
    this.handshake = null;
    this.stopMedia();
    if (this.dc) this.dc.close();
    if (this.pc) this.pc.close();
    this.connected = false;
    this.localVerified = false;
    this.remoteVerified = false;
    this.userVerified = false;
    this.peerIdentityFp = null;
    if (notify) this.onStateChange('disconnected');
  }

  /* ── Private ── */

  _newRTCPeerConnection() {
    // ICE servers come from the bounded /api/turn response. The documented
    // deployment uses self-hosted coturn rather than a public STUN provider.
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
      if (this._closed) return;
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
        identityPub: this.identity?.publicKeyRaw ?? null,
        onEstablished: (sas) => this._onEstablished(sas),
        onError: (reason) => {
          console.warn('[peer] handshake failed:', reason);
          this._terminateInsecure(reason);
        },
      });
      // Don't let a peer (or relay) that opens the channel but stalls the key
      // exchange leave us stuck "exchanging keys" forever — fail it after a bound.
      this._handshakeTimer = setTimeout(() => {
        if (!this.crypto.established) {
          console.warn('[peer] handshake did not complete in time — closing');
          this._terminateInsecure('handshake timed out');
        }
      }, HANDSHAKE_TIMEOUT_MS);
      try {
        await this.handshake.start();
      } catch (err) {
        console.warn('[peer] handshake start failed:', err);
        this._terminateInsecure('handshake start failed');
      }
    };

    ch.onmessage = async (e) => {
      if (typeof e.data !== 'string' || e.data.length > MAX_DATA_CHANNEL_MESSAGE) {
        console.warn('[peer] Received invalid message size — ignoring');
        return;
      }
      if (!this._consumeTrafficBudget(e.data.length)) {
        this._terminateInsecure('peer traffic limit exceeded');
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

      // Rekeys and app traffic arrive only in protocol-v5 sealed envelopes.
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
          await this._handleInner(inner);
        })
        .catch((err) => console.warn('[peer] failed to open sealed message', err));
      await this._recvQ;
    };

    ch.onclose = () => {
      if (!this._closed) this.close();
    };
  }

  _dcSend(obj) {
    if (this.dc && this.dc.readyState === 'open') this.dc.send(JSON.stringify(obj));
  }

  async _handleInner(inner) {
    if (!inner || typeof inner.type !== 'string') return;
    if (inner.type === 'rekey-offer') { await this._onRekeyOffer(inner); return; }
    if (inner.type === 'rekey-answer') { await this._onRekeyAnswer(inner); return; }
    if (inner.type === 'dtls-fp') { this._onPeerFingerprint(inner); return; }
    if (inner.type === 'identity-proof' && inner.v === PROTOCOL_VERSION) {
      await this._onIdentityProof(inner);
      return;
    }
    if (inner.type === 'verify-ready' && inner.v === PROTOCOL_VERSION) {
      this.remoteVerified = true;
      this._updateVerificationState();
      return;
    }
    if (!this.userVerified) {
      console.warn('[peer] dropping app traffic before identity verification');
      return;
    }
    await this.onMessage(inner);
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
    // can check it against the fingerprint signaling handed them. This binds
    // transport to the session; user verification is still a separate gate.
    this._verifyMediaPath();
    this._proveIdentity();
  }

  /**
   * Prove possession of the identity key presented in the handshake.
   *
   * Showing a public key is not evidence of holding it. Without this an attacker
   * could replay a saved contact's public key, match the pin, and be trusted
   * without the user ever comparing a safety code again. The signature covers
   * this session's transcript, so it cannot be lifted from another one.
   */
  _proveIdentity() {
    if (!this.identity || !this.crypto.transcriptHash) return;
    signTranscript(this.identity.privateKey, this.crypto.transcriptHash)
      .then((signature) => this._queueSealed({
        type: 'identity-proof',
        v: PROTOCOL_VERSION,
        sig: bufToB64(signature),
      }))
      .catch((err) => console.warn('[peer] identity proof failed', err));
  }

  async _onIdentityProof(msg) {
    const peerKey = this.handshake?.peerIdentityPub;
    if (!peerKey || this.peerIdentityFp) return;   // none offered, or already proved
    if (typeof msg.sig !== 'string' || !this.crypto.transcriptHash) return;
    let signature;
    try {
      signature = new Uint8Array(b64ToBuf(msg.sig));
    } catch {
      return;
    }
    const valid = await verifyTranscript(peerKey, this.crypto.transcriptHash, signature);
    if (!valid) {
      // A key was offered and the proof does not hold. That is not a benign
      // mismatch — abort rather than fall back to an unpinnable session.
      this._terminateInsecure('identity proof failed');
      return;
    }
    this.peerIdentityFp = await fingerprint(peerKey);
    this.onStateChange('identity-proved', this.peerIdentityFp);
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
    // leave mediaVerified false — calls stay disabled.
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
      this.boundFingerprints = theirs;
      this.onStateChange('media-verified');
    } else {
      // The peer's real DTLS cert differs from the SDP signaling relayed — a
      // man-in-the-middle is terminating the transport and could intercept a
      // call. Messages stayed confidential, but abort loudly.
      console.warn('[peer] DTLS fingerprint mismatch — media-path MITM');
      this._terminateInsecure('DTLS fingerprint mismatch — media path may be intercepted');
    }
  }

  /* ── Periodic DH key evolution — only the initiator drives the schedule ── */

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
        this._terminateInsecure('rekey timed out');
      }, REKEY_TIMEOUT_MS);
    });
    this._sendQ = operation.catch((err) => {
      console.warn('[peer] rekey offer failed', err);
      this._terminateInsecure('rekey failed');
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
      this._terminateInsecure('rekey failed');
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
      this._terminateInsecure('rekey failed');
    });
    return operation;
  }

  _requireVerifiedMedia() {
    if (!this.userVerified || !this.mediaVerified) {
      throw new Error('Peer identity or media path is not verified');
    }
  }

  /**
   * A renegotiation must keep using the certificate that was attested.
   *
   * The fingerprint comparison happens once, when the session is established.
   * Every SDP after that arrives over the encrypted channel, so it cannot be
   * rewritten in flight — but it can carry a different certificate, and
   * accepting one would silently move the media to a DTLS session nobody ever
   * vouched for. Re-checking costs nothing and makes the binding an invariant
   * rather than a one-time check.
   */
  _requireBoundCertificate(description) {
    if (!this.boundFingerprints) throw new Error('Media path is not bound');
    let offered = [];
    try {
      offered = extractFingerprints(description?.sdp || '');
    } catch { /* leave empty — the check below rejects it */ }
    if (!fingerprintsMatch(this.boundFingerprints, offered)) {
      throw new Error('Renegotiated media uses a different certificate');
    }
  }

  _updateVerificationState() {
    if (this.userVerified || !this.localVerified || !this.remoteVerified) return;
    this.userVerified = true;
    this.onStateChange('verified-ready');
  }

  _consumeTrafficBudget(bytes) {
    const now = Date.now();
    if (now - this._trafficWindowAt >= TRAFFIC_WINDOW_MS) {
      this._trafficWindowAt = now;
      this._trafficMessages = 0;
      this._trafficBytes = 0;
    }
    this._trafficMessages++;
    this._trafficBytes += bytes;
    return this._trafficMessages <= MAX_MESSAGES_PER_WINDOW
      && this._trafficBytes <= MAX_BYTES_PER_WINDOW;
  }

  _terminateInsecure(reason) {
    if (this._closed) return;
    this.close(false);
    this.onStateChange('insecure', reason);
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
