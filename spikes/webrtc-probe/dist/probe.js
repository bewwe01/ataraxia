// Veil Phase 1 spike: what WebRTC does this webview actually provide?
"use strict";
window.addEventListener("error", (e) => { try { invoke("report", { result: JSON.stringify({ jsError: String(e.message), at: e.filename + ":" + e.lineno }) }); } catch (_) { /* no bridge */ } });
window.addEventListener("unhandledrejection", (e) => { try { invoke("report", { result: JSON.stringify({ unhandledRejection: String(e.reason) }) }); } catch (_) { /* no bridge */ } });
function invoke(cmd, args) {
  return window.__TAURI__.core.invoke(cmd, args);
}
function withTimeout(p, ms, what) {
  return Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error(what + " timed out after " + ms + "ms")), ms))]);
}
async function loopback(policy) {
  const t0 = performance.now();
  const cfg = { iceServers: [], iceTransportPolicy: policy };
  const a = new RTCPeerConnection(cfg);
  const b = new RTCPeerConnection(cfg);
  const cands = { a: [], b: [] };
  const tag = (c) => c.type + (c.address && c.address.endsWith(".local") ? "/mdns" : "") + "/" + c.protocol;
  a.onicecandidate = (e) => { if (e.candidate) { cands.a.push(tag(e.candidate)); b.addIceCandidate(e.candidate).catch(() => {}); } };
  b.onicecandidate = (e) => { if (e.candidate) { cands.b.push(tag(e.candidate)); a.addIceCandidate(e.candidate).catch(() => {}); } };
  const ch = a.createDataChannel("probe");
  const got = new Promise((res) => { b.ondatachannel = (e) => { e.channel.onmessage = (m) => res(m.data); }; });
  ch.onopen = () => ch.send("ping-veil");
  await a.setLocalDescription(await a.createOffer());
  await b.setRemoteDescription(a.localDescription);
  await b.setLocalDescription(await b.createAnswer());
  await a.setRemoteDescription(b.localDescription);
  const sdp = a.localDescription.sdp;
  try {
    const message = await withTimeout(got, 8000, "datachannel loopback");
    return { ok: message === "ping-veil", ms: Math.round(performance.now() - t0), candidates: cands, fingerprintInSdp: /a=fingerprint:sha-256/i.test(sdp) };
  } catch (e) {
    return { ok: false, error: String(e), candidates: cands, iceState: [a.iceConnectionState, b.iceConnectionState] };
  } finally { a.close(); b.close(); }
}
(async () => {
  const out = {
    userAgent: navigator.userAgent,
    origin: location.origin,
    secureContext: window.isSecureContext,
    RTCPeerConnection: typeof window.RTCPeerConnection,
    RTCDataChannel: typeof window.RTCDataChannel,
    getUserMedia: !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia),
    RTCRtpScriptTransform: typeof window.RTCRtpScriptTransform,
  };
  if (out.RTCPeerConnection === "function") {
    try { out.loopbackAll = await loopback("all"); } catch (e) { out.loopbackAll = { ok: false, error: String(e) }; }
    try {
      const pc = new RTCPeerConnection({ iceServers: [], iceTransportPolicy: "relay" });
      out.relayPolicyAccepted = pc.getConfiguration().iceTransportPolicy === "relay";
      pc.close();
    } catch (e) { out.relayPolicyAccepted = "error: " + e; }
    try { const c = await RTCPeerConnection.generateCertificate({ name: "ECDSA", namedCurve: "P-256" }); out.generateCertificate = !!(c && c.getFingerprints ? c.getFingerprints().length : c); } catch (e) { out.generateCertificate = "error: " + e; }
  }
  if (out.getUserMedia) {
    try { out.mediaDeviceKinds = (await navigator.mediaDevices.enumerateDevices()).map((d) => d.kind); } catch (e) { out.mediaDeviceKinds = "error: " + e; }
  }
  document.getElementById("out").textContent = JSON.stringify(out, null, 2);
  await invoke("report", { result: JSON.stringify(out) });
})();
