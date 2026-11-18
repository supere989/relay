/* Exact-byte Ed25519 verification with the pinned local TweetNaCl verifier. */
"use strict";
(function (root) {
  const DOMAIN = "chatmail-archive-manager-response/v1\0";
  const MAX_RESPONSE = 22000;
  const ACTIONS = ["status", "refresh", "pause", "resume", "retry", "reconnect", "recovery", "unlink", "pair_start", "pair_confirm"];
  const encoder = new TextEncoder();
  const opaque = /^[0-9a-f]{32}$/;
  const token = /^[A-Za-z0-9_-]{32,192}$/;
  function fail(code) { throw new Error(code || "manager_protocol_invalid"); }
  function integer(value, minimum = 0) { if (!Number.isSafeInteger(value) || value < minimum) fail(); }
  function id(value, nullable = false) { if (!(nullable && value === null) && (typeof value !== "string" || !opaque.test(value))) fail(); }
  function capability(value, nullable = false) { if (!(nullable && value === null) && (typeof value !== "string" || !token.test(value))) fail(); }
  function choice(value, values) { if (typeof value !== "string" || !values.includes(value)) fail(); }
  function code(value) { if (value !== null && (typeof value !== "string" || !/^[a-z][a-z0-9_]{0,63}$/.test(value))) fail(); }
  function text(value, maximum = 160) {
    if (typeof value !== "string" || !value || encoder.encode(value).length > maximum) fail();
    for (const char of value) { const point = char.codePointAt(0); if (point < 32 || point === 127 || (point >= 0xd800 && point <= 0xdfff)) fail(); }
  }
  function keys(value, names) {
    if (!value || Array.isArray(value) || typeof value !== "object") fail();
    const actual = Object.keys(value).sort();
    if (actual.join("\0") !== names.slice().sort().join("\0")) fail();
  }
  function b64encode(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function b64decode(value, maximum, exact) {
    if (typeof value !== "string" || !value || value.length > Math.ceil(maximum * 4 / 3) || !/^[A-Za-z0-9_-]+$/.test(value)) fail();
    let binary;
    try { binary = atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4)); } catch (_) { fail(); }
    const bytes = Uint8Array.from(binary, char => char.charCodeAt(0));
    if (bytes.length > maximum || (exact !== undefined && bytes.length !== exact) || b64encode(bytes) !== value) fail();
    return bytes;
  }
  function safeParse(source) {
    // JSON.parse alone discards duplicate object members. Preserve that
    // rejection contract and bound recursion before building a state object.
    let position = 0, nodes = 0;
    function space() { while (/[\x20\t\r\n]/.test(source[position] || "x")) position++; }
    function string() {
      const begin = position++;
      while (position < source.length) {
        const char = source[position++];
        if (char === '"') { try { return JSON.parse(source.slice(begin, position)); } catch (_) { fail(); } }
        if (char === "\\") position++;
        else if (char.charCodeAt(0) < 32) fail();
      }
      fail();
    }
    function parse(depth) {
      if (depth > 16 || ++nodes > 4096) fail();
      space();
      const char = source[position];
      if (char === '"') return string();
      if (char === "{") {
        position++; const object = Object.create(null); space();
        if (source[position] === "}") { position++; return object; }
        while (position < source.length) {
          space(); if (source[position] !== '"') fail();
          const key = string();
          if (["__proto__", "constructor", "prototype"].includes(key) || Object.prototype.hasOwnProperty.call(object, key)) fail();
          space(); if (source[position++] !== ":") fail();
          object[key] = parse(depth + 1); space();
          const end = source[position++];
          if (end === "}") return object;
          if (end !== ",") fail();
        }
        fail();
      }
      if (char === "[") {
        position++; const array = []; space();
        if (source[position] === "]") { position++; return array; }
        while (position < source.length) {
          array.push(parse(depth + 1)); space(); const end = source[position++];
          if (end === "]") return array;
          if (end !== ",") fail();
        }
        fail();
      }
      for (const [literal, value] of [["true", true], ["false", false], ["null", null]]) {
        if (source.startsWith(literal, position)) { position += literal.length; return value; }
      }
      const match = /^-?(?:0|[1-9][0-9]*)/.exec(source.slice(position));
      if (!match) fail();
      position += match[0].length;
      const value = Number(match[0]); if (!Number.isSafeInteger(value)) fail(); return value;
    }
    const value = parse(0); space(); if (position !== source.length) fail(); return value;
  }
  function url(value, origin, originOnly = false) {
    text(value, 2048); let parsed;
    try { parsed = new URL(value); } catch (_) { fail("manager_portal_url_invalid"); }
    if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.hash || value.includes("\\") || (origin && parsed.origin !== origin) || (originOnly && value !== parsed.origin)) fail("manager_portal_url_invalid");
    return value;
  }
  function bootstrap(value) {
    keys(value, ["version", "instance", "profile_epoch", "public_key", "portal_origin"]);
    if (value.version !== 1) fail(); id(value.instance); id(value.profile_epoch); b64decode(value.public_key, 32, 32); url(value.portal_origin, null, true); return value;
  }
  function document(value, origin) {
    keys(value, ["version", "instance", "profile_epoch", "command_id", "revision", "issued_at", "expires_at", "state", "result", "code", "action", "bindings", "leases", "pairing", "handoff"]);
    if (value.version !== 1) fail(); id(value.instance); id(value.profile_epoch); id(value.command_id, true);
    ["revision", "issued_at", "expires_at"].forEach(name => integer(value[name]));
    if (!(value.expires_at > value.issued_at && value.expires_at - value.issued_at <= 600)) fail();
    choice(value.state, ["unlinked", "pairing", "linked", "refused"]); choice(value.result, ["snapshot", "queued", "confirmed", "rejected"]); code(value.code);
    if (value.action !== null) choice(value.action, ACTIONS);
    if (!Array.isArray(value.bindings) || value.bindings.length > 16 || !value.leases || Array.isArray(value.leases) || typeof value.leases !== "object") fail();
    const handles = new Set();
    for (const binding of value.bindings) {
      keys(binding, ["binding", "label", "state", "enabled", "generation", "link_revision", "unresolved", "held_unresolved", "eligible_unresolved", "last_verified", "jobs", "jobs_omitted", "queued_jobs", "verified_files", "coverage"]);
      id(binding.binding); if (handles.has(binding.binding)) fail(); handles.add(binding.binding); text(binding.label);
      choice(binding.state, ["pending", "active", "declined", "revoked", "paused", "opted-out", "expired"]); if (typeof binding.enabled !== "boolean") fail();
      choice(binding.coverage, ["capture-windows", "incomplete", "unknown"]);
      ["generation", "link_revision", "unresolved", "held_unresolved", "eligible_unresolved", "jobs_omitted", "queued_jobs", "verified_files"].forEach(name => integer(binding[name], name === "generation" ? 1 : 0));
      if (binding.held_unresolved + binding.eligible_unresolved > binding.unresolved || (binding.eligible_unresolved && (!binding.enabled || binding.state !== "active"))) fail();
      if (binding.last_verified !== null) integer(binding.last_verified);
      if (binding.coverage === "capture-windows" && (!binding.verified_files || binding.last_verified === null || binding.unresolved)) fail();
      if (!Array.isArray(binding.jobs) || binding.jobs.length > 8) fail();
      const jobs = new Set();
      for (const job of binding.jobs) {
        keys(job, ["job", "state", "reason"]); id(job.job); if (jobs.has(job.job)) fail(); jobs.add(job.job);
        choice(job.state, ["queued", "prepared", "uploading", "uploaded-unverified", "verified", "incomplete", "failed", "uncertain", "paused"]); code(job.reason);
      }
    }
    for (const [handle, leases] of Object.entries(value.leases)) {
      if (!handles.has(handle) || !leases || Array.isArray(leases) || typeof leases !== "object") fail();
      for (const [action, lease] of Object.entries(leases)) { choice(action, ["pause", "resume", "retry", "reconnect", "recovery", "unlink"]); capability(lease); }
    }
    if (value.pairing !== null) {
      const pair = value.pairing;
      keys(pair, ["phase", "url", "comparison", "challenge", "intent", "peer_label", "lease"]);
      choice(pair.phase, ["open_browser", "confirm_app", "browser_confirm"]); url(pair.url, origin); id(pair.challenge); text(pair.peer_label);
      if (typeof pair.comparison !== "string" || !/^[0-9]{6}$/.test(pair.comparison)) fail();
      id(pair.intent, pair.phase !== "confirm_app"); capability(pair.lease, pair.phase !== "confirm_app");
    }
    if (value.handoff !== null) { keys(value.handoff, ["action", "url"]); choice(value.handoff.action, ["reconnect", "recovery"]); url(value.handoff.url, origin); }
    return value;
  }
  function signed(envelope, context) {
    if (encoder.encode(JSON.stringify({payload: envelope})).length > 32768) fail("manager_protocol_size");
    keys(envelope, ["version", "type", "payload", "signature"]);
    if (envelope.version !== 1 || envelope.type !== "archive-manager-response") fail();
    const raw = b64decode(envelope.payload, MAX_RESPONSE), signature = b64decode(envelope.signature, 64, 64), publicKey = b64decode(context.public_key, 32, 32);
    const prefix = encoder.encode(DOMAIN), input = new Uint8Array(prefix.length + raw.length); input.set(prefix); input.set(raw, prefix.length);
    if (!root.nacl.sign.detached.verify(input, signature, publicKey)) fail("manager_signature_invalid");
    // No state JSON is parsed or displayed before signature verification.
    let source; try { source = new TextDecoder("utf-8", {fatal: true, ignoreBOM: true}).decode(raw); } catch (_) { fail(); }
    const value = document(safeParse(source), context.portal_origin);
    if (value.instance !== context.instance || value.profile_epoch !== context.profile_epoch) fail("manager_instance_mismatch");
    return value;
  }
  function verify(envelope, context, now, minimum = 0) {
    const value = signed(envelope, context);
    if (value.expires_at <= now || value.issued_at > now + 30) fail("manager_response_expired");
    if (value.revision < minimum) fail("manager_response_stale");
    return value;
  }
  root.ArchiveManagerProtocol = Object.freeze({bootstrap, verify, previewCached: signed, b64encode, safeParse, utf8Bytes: value => encoder.encode(value).length});
})(typeof window === "undefined" ? self : window);
