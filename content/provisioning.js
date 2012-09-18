window.addEventListener("message", function(event) {
  if (event.origin != document.location.protocol + "//" + document.domain) {
    return; // Not from ourselves
  }
  try {
    if (event.data.origin == "browseridp-client") {
      return;
    }
  } catch (ex) {}
  if (event.data.origin != "browseridp-host") {
    return;
  }
  navigator.id[event.data.command].apply(navigator.id, event.data.args);
}, false);

function start() {
  dump("being provisioning...");
  navigator.id.beginProvisioning(function(email, cert_duration) {
    let host = String(email).replace(/^.*@/, "");
    if (host != document.domain) {
      navigator.id.raiseProvisioningFailure("BrowserIdP cannot provision for host " + host);
      return;
    }
    cert_duration = Math.min(cert_duration, 60 * 10); // at most 10 minutes
    cert_duration = Math.max(cert_duration, 60 * 1); // at least 1 minute
    // XXX Mook: the spec says seconds-since-epoch, but the reference
    // implementation takes millisecons-since-epoch (JS new Date())
    let cert_expiry = Date.now() + cert_duration * 1000;

    // Assume for now we have a key for this host; we can fail later.
    navigator.id.genKeyPair(function(pubkey) {
      sign({
          email: email,
          expiry: cert_expiry,
          pubkey: pubkey,
        });
    });
  });
}

dump("privisioning script ready.");
