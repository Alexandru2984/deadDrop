/**
 * Dead Drop — P2P Connection Layer
 *
 * Manages a single WebRTC peer connection with a data channel.
 * The signaling object must expose a `send(msg)` method.
 * Key exchange happens over the data channel (not the signaling server)
 * so the server never sees encryption keys.
 */

import { Handshake } from './handshake.js';

const MAX_DATA_CHANNEL_MESSAGE = 256 * 1024;
const REKEY_INTERVAL_MS = 10 * 60 * 1000; // DH ratchet every 10 min for forward secrecy

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

  /** Send a plain JS object over the data channel (caller encrypts first). */
  send(obj) {
    if (!this.dc || this.dc.readyState !== 'open') {
      throw new Error('Data channel not open');
    }
    this.dc.send(JSON.stringify(obj));
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

      // Key-exchange and rekey traffic is handled here, never forwarded to the app.
      if (msg.type === 'kex-commit' || msg.type === 'kex-reveal') {
        if (this.handshake) {
          try { await this.handshake.handle(msg); } catch (err) { console.warn('[peer] kex error', err); }
        }
        return;
      }
      if (msg.type === 'rekey-offer')  { await this._onRekeyOffer(msg);  return; }
      if (msg.type === 'rekey-answer') { await this._onRekeyAnswer(msg); return; }

      // Everything else only makes sense once the session is encrypted.
      if (!this.crypto.established) {
        console.warn('[peer] dropping pre-handshake app message');
        return;
      }
      this.onMessage(msg);
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

  _onEstablished(sas) {
    this.onStateChange('encrypted', sas);
    if (this.isInitiator) this._scheduleRekey();
  }

  /* ── DH ratchet (forward secrecy) — only the initiator drives the schedule ── */

  _scheduleRekey() {
    this._clearRekey();
    this._rekeyTimer = setTimeout(() => this._doRekey(), REKEY_INTERVAL_MS);
  }

  _clearRekey() {
    if (this._rekeyTimer) { clearTimeout(this._rekeyTimer); this._rekeyTimer = null; }
  }

  async _doRekey() {
    if (!this.crypto.established || !this.dc || this.dc.readyState !== 'open') return;
    try {
      const offer = await this.crypto.beginRekey();
      this._dcSend({ type: 'rekey-offer', epoch: offer.epoch, publicKey: offer.publicKey });
    } catch (err) {
      console.warn('[peer] rekey offer failed', err);
      this._scheduleRekey(); // retry next interval
    }
  }

  async _onRekeyOffer(msg) {
    if (!this.crypto.established || typeof msg.publicKey !== 'string' || !Number.isInteger(msg.epoch)) return;
    try {
      const answer = await this.crypto.acceptRekey(msg.publicKey, msg.epoch);
      this._dcSend({ type: 'rekey-answer', epoch: answer.epoch, publicKey: answer.publicKey });
    } catch (err) {
      console.warn('[peer] rekey accept failed — tearing down to avoid key divergence', err);
      this.onStateChange('insecure', 'rekey failed');
      this.close();
    }
  }

  async _onRekeyAnswer(msg) {
    if (typeof msg.publicKey !== 'string' || !Number.isInteger(msg.epoch)) return;
    try {
      await this.crypto.completeRekey(msg.publicKey, msg.epoch);
      this._scheduleRekey(); // line up the next ratchet
    } catch (err) {
      console.warn('[peer] rekey complete failed — tearing down to avoid key divergence', err);
      this.onStateChange('insecure', 'rekey failed');
      this.close();
    }
  }
}
