/**
 * Dead Drop — P2P Connection Layer
 *
 * Manages a single WebRTC peer connection with a data channel.
 * The signaling object must expose a `send(msg)` method.
 * Key exchange happens over the data channel (not the signaling server)
 * so the server never sees encryption keys.
 */

import { bufToB64, b64ToBuf } from './util.js';

export class PeerConnection {
  /**
   * @param {Object}      signaling    – { send(msg) }
   * @param {CryptoLayer} cryptoLayer  – shared crypto instance
   * @param {Function}    onMessage    – called with each decrypted peer message
   * @param {Function}    onStateChange – called with 'connected' | 'encrypted' | 'disconnected'
   */
  constructor(signaling, cryptoLayer, onMessage, onStateChange) {
    this.signaling = signaling;
    this.crypto = cryptoLayer;
    this.onMessage = onMessage;
    this.onStateChange = onStateChange;
    this.pc = null;
    this.dc = null;            // data channel
    this.remotePeerId = null;
    this.connected = false;
    this.onRemoteTrack = null; // callback for incoming remote media
    this.localStream = null;
  }

  /* ── Initiator (caller) ── */

  async createOffer(remotePeerId) {
    this.remotePeerId = remotePeerId;
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
    this.stopMedia();
    if (this.dc) this.dc.close();
    if (this.pc) this.pc.close();
    this.connected = false;
    this.onStateChange('disconnected');
  }

  /* ── Private ── */

  _newRTCPeerConnection() {
    const pc = new RTCPeerConnection({
      iceServers: [{ urls: 'stun:stun.l.google.com:19302' }],
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
      // Initiate ephemeral key exchange over the data channel
      const pubKey = await this.crypto.generateKeyPair();
      ch.send(JSON.stringify({
        type: 'key-exchange',
        publicKey: bufToB64(pubKey),
      }));
    };

    ch.onmessage = async (e) => {
      const msg = JSON.parse(e.data);

      if (msg.type === 'key-exchange') {
        // Derive the shared secret from the peer's public key
        await this.crypto.deriveSharedKey(b64ToBuf(msg.publicKey));
        // Compute SAS fingerprint for MitM verification
        const sas = await this.crypto.computeSAS();
        this.onStateChange('encrypted', sas);
        return;
      }

      // All other messages are forwarded to the application layer
      this.onMessage(msg);
    };

    ch.onclose = () => {
      this.connected = false;
      this.onStateChange('disconnected');
    };
  }
}
