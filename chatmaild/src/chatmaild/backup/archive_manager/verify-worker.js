"use strict";
importScripts("vendor/nacl-fast.min.js", "protocol.js");
let context = null;
self.onmessage = function (event) {
  const message = event.data;
  try {
    if (message.type === "init" && context === null) {
      context = self.ArchiveManagerProtocol.bootstrap(message.context);
      self.postMessage({type: "ready"});
      return;
    }
    if (!context || message.type !== "verify") return;
    const value = message.history
      ? self.ArchiveManagerProtocol.previewCached(message.envelope, context)
      : self.ArchiveManagerProtocol.verify(message.envelope, context, message.now, message.minimum);
    self.postMessage({type: "verified", id: message.id, value});
  } catch (error) {
    self.postMessage({type: "denied", id: message.id, code: ["manager_response_stale", "manager_response_expired"].includes(error.message) ? error.message : "manager_signature_invalid"});
  }
};
