"use strict";
(function () {
  const $ = id => document.getElementById(id);
  const protocol = window.ArchiveManagerProtocol;
  let context, snapshot = null, envelope = null, selected = null, authoritative = false;
  let lastRevision = -1, lastPayload = null, queue = [], nextSend = 0, queueTimer = null;
  let worker = null, workerReady = false, fixedPortal = false, historyComplete = false, verificationId = 0, deferred = null, ignored = 0;
  const verification = new Map();
  const pending = new Map();
  const accepted = new Set();
  const unknownOutcomes = new Map();
  let earlierUnknownOutcome = false;
  const now = () => Math.floor(Date.now() / 1000);
  const isReadAction = action => ["status", "refresh", "pair_start"].includes(action);
  const feedback = text => {
    const unknown = unknownOutcomes.size || earlierUnknownOutcome ? " An earlier request's outcome is unknown. It was not sent again." : "";
    const blocked = Array.from(unknownOutcomes.values()).some(item => item.blocked) ? " Its controls remain blocked while the earlier request could still apply." : "";
    $("feedback").textContent = text + unknown + blocked;
  };
  function verificationEvent() { ignored++; $("verification-events").textContent = "Delayed or rejected verification events this session: " + ignored + ". No private update contents are recorded."; }
  const friendly = {
    manager_lease_expired: "This control expired. Refresh status and try again.",
    manager_revision_changed: "The mailbox changed on another device. Refresh before trying again.",
    binding_operation_busy: "Another archive operation is still running. Please try again shortly.",
    manager_owner_changed: "This mailbox link needs to be verified again in the portal.",
    manager_link_missing: "This conversation no longer has access to that mailbox.",
    consent_required: "Reconnect Drive in the secure portal to continue.",
    invalid_grant: "Drive access expired. Reconnect in the secure portal.",
    quota_exceeded: "Drive storage is full. Free space in Drive, then retry.",
    source_changed: "A message changed during capture. A later scan can try again.",
    manager_rate_limit: "The service is busy. Wait briefly, then refresh.",
    manager_instance_invalid: "Ask the verified archive service for a new Archive Manager app."
  };
  const stateNames = {pending: "Waiting for Drive consent", active: "Archiving enabled", declined: "Drive consent declined", revoked: "Drive access needs renewal", paused: "Archiving paused", "opted-out": "Archiving turned off", expired: "Drive access expired"};
  const jobNames = {queued: "Queued for the archive worker", prepared: "Encrypted and waiting to upload", uploading: "Upload in progress", "uploaded-unverified": "Uploaded; verification still pending", verified: "Downloaded and verified", incomplete: "Some messages need attention", failed: "Retry needed", uncertain: "Upload outcome is being reconciled", paused: "Waiting for access or consent"};

  function fresh() { return authoritative && snapshot && snapshot.expires_at > now(); }
  function binding() { return snapshot && snapshot.bindings.find(item => item.binding === selected); }
  function leases() { return fresh() && snapshot.leases[selected] || {}; }
  function hasPending(handle) { return Array.from(pending.values()).concat(queue.map(item => item.command)).some(item => item.binding === handle && !isReadAction(item.action)); }
  function reconcileUnknown(value, request, history) {
    // Only a live answer to this session's read-only request is evidence. The
    // global revision and client clock say nothing about an old lease's power.
    if (history || !request || !["status", "refresh"].includes(request.action) || value.action !== request.action || value.result !== "snapshot") return;
    for (const [id, waiting] of pending) {
      if (isReadAction(waiting.action)) continue;
      const current = value.bindings.find(item => item.binding === waiting.binding);
      const absent = waiting.binding !== null && !current;
      const advanced = current && current.generation >= waiting.generation && current.link_revision >= waiting.link_revision && (current.generation > waiting.generation || current.link_revision > waiting.link_revision);
      // The service caps persisted leases at their signed snapshot expiry.
      // An extra whole second covers rounding; no local-clock expiry unlocks.
      const expired = Number.isSafeInteger(waiting.priorExpires) && value.issued_at > waiting.priorExpires + 1;
      const safe = absent || advanced || expired;
      if (safe) {
        pending.delete(id); accepted.delete(id); unknownOutcomes.delete(id);
        earlierUnknownOutcome = true; // Bounded aggregate, no identifier history.
      } else unknownOutcomes.set(id, {blocked: true});
    }
  }
  function enableControls() {
    const current = binding(), enabled = workerReady && fresh() && current && !hasPending(selected);
    $("refresh").disabled = !workerReady || !window.webxdc;
    for (const action of ["pause", "resume", "reconnect", "recovery", "unlink"]) $(action).disabled = !enabled || !leases()[action];
    if (current) {
      $("pause").disabled = $("pause").disabled || !current.enabled;
      $("resume").disabled = $("resume").disabled || current.enabled;
      $("pause").title = current.enabled ? "Stop future archive work" : "Archiving is already turned off";
      $("resume").title = current.enabled ? "Archiving is already enabled" : "Resume future archive work";
    }
    $("pair-start").disabled = !workerReady || !window.webxdc || queue.length >= 8;
    $("add-mailbox").disabled = !workerReady || !window.webxdc || queue.length >= 8;
    $("pair-confirm").disabled = !workerReady || !fresh() || !snapshot.pairing || snapshot.pairing.phase !== "confirm_app" || !snapshot.pairing.lease || hasPending(null);
    document.querySelectorAll("button[data-retry]").forEach(button => { button.disabled = !enabled || !leases().retry; });
  }
  function showPortal(url) {
    // The verifier has already restricted the signed URL to the embedded
    // HTTPS portal origin. Only a deliberate link click may leave the app.
    $("handoff-panel").hidden = false;
    $("portal-url").value = url;
    $("portal-link").href = url;
  }
  function hidePortal() { $("handoff-panel").hidden = true; $("portal-link").removeAttribute("href"); $("portal-url").value = ""; }
  function renderBinding() {
    const current = binding();
    $("mailbox-panel").hidden = !current;
    if (!current) return;
    $("archive-state").textContent = stateNames[current.state] || "Archive status needs attention";
    const hasVerifiedArchive = current.verified_files > 0 && current.last_verified !== null;
    $("coverage").textContent = !hasVerifiedArchive ? (current.unresolved ? "No verified archive yet. Coverage is incomplete; some messages need attention." : "No verified archive yet. Coverage has not been confirmed.") : current.coverage === "unknown" ? "Archive coverage has not been confirmed. Refresh to check the latest results." : current.coverage === "incomplete" || current.unresolved ? "Coverage incomplete — unresolved messages still need attention." : "Verified capture windows only. This does not confirm a complete mailbox backup.";
    $("last-verified").textContent = current.last_verified === null ? "No verified archive yet" : new Date(current.last_verified * 1000).toLocaleString();
    $("verified-files").textContent = String(current.verified_files);
    $("queued-jobs").textContent = String(current.queued_jobs);
    $("unresolved").textContent = String(current.unresolved);
    $("eligible-unresolved").textContent = String(current.eligible_unresolved);
    $("held-unresolved").textContent = String(current.held_unresolved);
    $("archive-help").textContent = current.held_unresolved ? "Some message retries are on hold and need your action in the secure portal." : !current.enabled && current.unresolved ? "Archiving is off. Unresolved messages are not queued for automatic retries." : current.eligible_unresolved ? "Some messages are waiting for another attempt while archiving and Drive access remain active." : current.queued_jobs ? "Queued work is not a verified Drive file. Keep using mail normally while the separate worker runs." : "Turning archiving off stops future work; existing Drive archives remain.";
    $("jobs-omitted").hidden = !current.jobs_omitted;
    $("jobs-omitted").textContent = current.jobs_omitted ? String(current.jobs_omitted) + " additional work items are not shown in this recent list. Mailbox controls and totals are unchanged." : "";
    const list = $("jobs"); list.replaceChildren();
    if (!current.jobs.length) { const item = document.createElement("li"); item.textContent = current.jobs_omitted ? "Recent details are not shown here. See the totals above." : "No recent work to show."; list.append(item); }
    for (const job of current.jobs) {
      const item = document.createElement("li"), status = document.createElement("p");
      status.textContent = jobNames[job.state]; item.append(status);
      if (job.reason) { const help = document.createElement("p"); help.textContent = friendly[job.reason] || "Open the secure portal for details, or refresh and try again."; item.append(help); }
      if (["failed", "incomplete", "paused", "uncertain"].includes(job.state)) {
        const retry = document.createElement("button"); retry.type = "button"; retry.textContent = "Retry this work"; retry.dataset.retry = job.job;
        retry.addEventListener("click", () => request("retry", {job: job.job})); item.append(retry);
      }
      list.append(item);
    }
  }
  function render() {
    if (!snapshot) { $("pair-panel").hidden = false; enableControls(); return; }
    $("connection").textContent = fresh() ? "Status verified from the archive service. Refresh to check for changes." : "Earlier status — refresh to check current information. Controls are unavailable.";
    $("updated").textContent = "Status as of: " + new Date(snapshot.issued_at * 1000).toLocaleString();
    const select = $("mailbox"); select.replaceChildren();
    if (!snapshot.bindings.some(item => item.binding === selected)) selected = snapshot.bindings.length ? snapshot.bindings[0].binding : null;
    for (const item of snapshot.bindings) { const option = document.createElement("option"); option.value = item.binding; option.textContent = item.label; select.append(option); }
    if (selected) select.value = selected;
    renderBinding();
    $("pair-panel").hidden = !!snapshot.bindings.length && !snapshot.pairing;
    $("pair-details").hidden = !snapshot.pairing;
    fixedPortal = false; hidePortal();
    if (snapshot.pairing) {
      const pair = snapshot.pairing;
      $("comparison").textContent = pair.comparison;
      $("pair-peer").textContent = "Service identity: " + pair.peer_label;
      $("pair-instruction").textContent = pair.phase === "confirm_app" ? "Confirm only if this browser request and service identity are yours. Then finish in the browser." : pair.phase === "browser_confirm" ? "App confirmation received. Return to the same browser and confirm there." : "Open the portal and compare this code there. Then refresh this app to review your browser request. Do not send the code or forward both pairing channels to anyone.";
      $("pair-confirm").hidden = pair.phase !== "confirm_app";
      if (fresh()) showPortal(pair.url);
    }
    if (fresh() && snapshot.handoff) showPortal(snapshot.handoff.url);
    enableControls();
  }
  function applyVerified(value, candidate, history) {
    try {
      if (value.revision < lastRevision) throw new Error("manager_response_stale");
      if (value.revision === lastRevision) {
        if (candidate.payload !== lastPayload) throw new Error("manager_response_stale");
        return;
      }
      lastRevision = value.revision; lastPayload = candidate.payload;
      const request = !history && value.command_id ? pending.get(value.command_id) : null;
      const acknowledgment = !history && value.command_id && (pending.has(value.command_id) || accepted.has(value.command_id));
      snapshot = value; envelope = candidate; authoritative = !!acknowledgment;
      reconcileUnknown(value, request, history);
      // A queued acknowledgment is not the terminal outcome. Keep its exact
      // binding/expiry record until confirmed, rejected or safely reconciled.
      if (!history && value.command_id && value.result !== "queued") pending.delete(value.command_id);
      if (acknowledgment && value.result === "queued") { accepted.add(value.command_id); if (accepted.size > 16) accepted.delete(accepted.values().next().value); }
      if (acknowledgment && ["confirmed", "rejected"].includes(value.result)) { accepted.delete(value.command_id); unknownOutcomes.delete(value.command_id); }
      if (history) feedback("Earlier verified status restored from chat history. Waiting for a new service response.");
      else if (!acknowledgment) feedback("An earlier update did not answer this session's request. Refresh to confirm current controls.");
      else if (acknowledgment && value.result === "queued") feedback("The service accepted your request. Archive work is queued, not yet verified.");
      else if (acknowledgment && value.result === "confirmed") feedback("The service confirmed this change.");
      else if (acknowledgment && value.result === "rejected") feedback(friendly[value.code] || "The service could not apply this request. Refresh or continue in the secure portal.");
      else if (Array.from(pending.values()).some(item => !isReadAction(item.action))) feedback("Verified status received. Your earlier request is still waiting for its own service acknowledgment.");
      else feedback("Verified status received.");
      render();
    } catch (_) { verificationEvent(); feedback("An older update was ignored."); }
  }
  function accept(update) {
    const candidate = update && update.payload;
    if (!candidate || candidate.type !== "archive-manager-response") return; // Commands/self echoes are not state.
    try {
      if (protocol.utf8Bytes(JSON.stringify({payload: candidate})) > 32768) throw new Error("oversized");
      const record = {candidate, history: !historyComplete};
      if (verification.size >= 32) { deferred = record; verificationEvent(); feedback("Many updates are waiting for verification. Refresh to request current status."); return; }
      verifyRecord(record);
    } catch (_) { verificationEvent(); feedback("An invalid or oversized update was ignored."); }
  }
  function verifyRecord(record) {
    const id = ++verificationId;
    verification.set(id, record);
    worker.postMessage({type: "verify", id, envelope: record.candidate, history: record.history, now: now(), minimum: Math.max(0, lastRevision)});
  }
  function unsupported() {
    workerReady = false; authoritative = false; verification.clear(); queue = [];
    if (worker) worker.terminate(); worker = null;
    $("connection").textContent = "This client cannot run the local signature-verification worker. No archive state or controls are trusted here. Use an updated Delta Chat client or the secure portal.";
    $("mailbox-panel").hidden = true; $("pair-panel").hidden = true;
    fixedPortal = true; showPortal(context.portal_origin); enableControls();
  }
  function flush() {
    queueTimer = null;
    if (!queue.length) return;
    const delay = Math.max(0, nextSend - Date.now());
    if (delay) { queueTimer = setTimeout(flush, delay); return; }
    const queued = queue.shift(), command = queued.command;
    pending.set(command.id, {...command, priorExpires: queued.priorExpires});
    try {
      // sendUpdate's durable messaging queue is the transport. Sending is not
      // a service acknowledgment and never changes the authoritative snapshot.
      const delivery = window.webxdc.sendUpdate({payload: command}, "");
      if (delivery && typeof delivery.catch === "function") delivery.catch(() => { sendFailed(command); });
      feedback("Sending through Delta Chat. Waiting for the bot's signed response; no change is confirmed yet.");
      const interval = window.webxdc.sendUpdateInterval;
      nextSend = Date.now() + (Number.isFinite(interval) && interval >= 0 ? Math.max(1, interval) : 10000);
    } catch (_) { sendFailed(command); }
    enableControls();
    if (queue.length) queueTimer = setTimeout(flush, Math.max(1, nextSend - Date.now()));
  }
  function sendFailed(command) {
    if (isReadAction(command.action)) pending.delete(command.id);
    else unknownOutcomes.set(command.id, {blocked: true});
    feedback("Delta Chat could not confirm sending this request. Refresh status before trying another change.");
    enableControls();
  }
  function request(action, args = {}) {
    try {
      if (!workerReady || !window.webxdc || queue.length >= 8 || (pending.size >= 8 && !isReadAction(action))) { feedback("Too many requests are waiting. Keep this app open and refresh shortly."); return; }
      const pair = snapshot && snapshot.pairing;
      const pairAction = action === "pair_start" || action === "pair_confirm";
      const current = pairAction ? null : binding();
      const read = isReadAction(action);
      if (read && pending.size >= 8) for (const [id, waiting] of pending) if (isReadAction(waiting.action)) pending.delete(id);
      let lease = read ? null : action === "pair_confirm" ? pair && pair.lease : leases()[action];
      if (!read && hasPending(current ? current.binding : null)) { feedback("An earlier request is still waiting. Refresh to check its status before another change."); return; }
      if (!read && (!fresh() || !lease)) { feedback("This control is stale. Refresh status before trying again."); return; }
      if (action === "pair_confirm") args = {challenge: pair.challenge, intent: pair.intent};
      const command = {version: 1, type: "archive-manager-command", instance: context.instance,
        id: Array.from(window.nacl.randomBytes(16), byte => byte.toString(16).padStart(2, "0")).join(""), action, binding: current ? current.binding : null,
        link_revision: current ? current.link_revision : 0, generation: current ? current.generation : 0, lease, args};
      const size = protocol.utf8Bytes(JSON.stringify({payload: command}));
      const advertised = window.webxdc.sendUpdateMaxSize;
      if (size > 4096 || size > (Number.isFinite(advertised) && advertised > 0 ? advertised : 128000)) { feedback("This request exceeds your client's message limit. Open the secure portal instead."); return; }
      queue.push({command, priorExpires: snapshot ? snapshot.expires_at : null});
      feedback("Waiting for Delta Chat's sending interval. Keep this app open.");
      enableControls();
      if (!queueTimer) flush();
    } catch (_) { feedback("This client cannot create a secure request. Update Delta Chat or use the secure portal."); }
  }
  try {
    context = protocol.bootstrap(window.ARCHIVE_MANAGER_BOOTSTRAP);
    $("refresh").addEventListener("click", () => request("refresh"));
    $("pair-start").addEventListener("click", () => request("pair_start"));
    $("add-mailbox").addEventListener("click", () => request("pair_start"));
    $("pair-confirm").addEventListener("click", () => request("pair_confirm"));
    $("mailbox").addEventListener("change", () => { selected = $("mailbox").value; renderBinding(); enableControls(); });
    for (const action of ["pause", "resume", "reconnect", "recovery", "unlink"]) $(action).addEventListener("click", () => request(action));
    $("copy-url").addEventListener("click", () => { $("portal-url").focus(); $("portal-url").select(); feedback("Address selected. Copy it and check the portal address in your browser."); });
    $("portal-link").addEventListener("click", event => { if (!fixedPortal && !fresh()) { event.preventDefault(); feedback("This link expired. Refresh for a new secure portal link."); } });
    render();
    if (!window.webxdc || typeof window.webxdc.setUpdateListener !== "function" || typeof window.webxdc.sendUpdate !== "function") {
      $("refresh").disabled = true; feedback("Open the registered app in its verified private Delta Chat service conversation.");
    } else {
      try {
        worker = new Worker("verify-worker.js");
        const startup = setTimeout(() => { if (!workerReady) unsupported(); }, 5000);
        worker.onerror = unsupported;
        worker.onmessage = event => {
          if (!worker) return;
          const result = event.data;
          if (result.type === "ready") {
            clearTimeout(startup); workerReady = true; enableControls();
            Promise.resolve(window.webxdc.setUpdateListener(accept, 0)).then(() => { historyComplete = true; request("status"); }).catch(() => feedback("Delta Chat could not read app updates. Reopen the app and try again."));
            return;
          }
          const record = verification.get(result.id);
          if (!record) return;
          verification.delete(result.id);
          if (result.type === "verified") applyVerified(result.value, record.candidate, record.history);
          else { verificationEvent(); feedback(result.code === "manager_response_stale" ? "An older update was ignored." : result.code === "manager_response_expired" ? "An expired update was ignored. Refresh for current status." : "An unverified or unrelated update was ignored."); }
          if (deferred && verification.size < 32) { const next = deferred; deferred = null; verifyRecord(next); }
        };
        worker.postMessage({type: "init", context});
      } catch (_) { unsupported(); }
    }
    setInterval(() => { if (authoritative && !fresh()) { authoritative = false; render(); } }, 1000);
    document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible" && !fresh()) { authoritative = false; render(); } });
  } catch (_) { $("connection").textContent = "This app's public service context could not be verified. Ask the verified service for a new app."; $("refresh").disabled = true; }
})();
