(function() {
  function dump(data) {
    window.postMessage({
      origin: "browseridp-client",
      command: "dump",
      data: data
    }, "*");
  }
  function dispatch(method, params) {
    let data = {};
    for (let [k, v] in Iterator(params)) data[k] = v;
    data.origin = "browseridp-client";
    data.command = method;
    window.postMessage(data, "*");
  }
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
  if (!navigator.id) {
    try {
      BuildShim();
    } catch (e) {
      dump(String(e) + "\n\n" + JSON.stringify(e));
    }
  }
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
      dispatch('sign', {
          email: email,
          expiry: cert_expiry,
          pubkey: pubkey,
        });
    });
  });

  function BuildShim() {
    dump("Building shim...");
    navigator.id = {
      beginProvisioning: function(cb) {
        if (typeof cb !== 'function') {
          throw ".beginProvisioning() requires a callback argument";
        }
        this.__call("beginProvisioning",
                    function(r) {
                      cb(r.email, r.cert_duration_s);
                    });
      },
      genKeyPair: function(cb) {
        if (typeof cb !== 'function') {
          throw ".genKeyPair() requires a callback argument";
        }
        this.__call("genKeyPair", function(k) cb(JSON.parse(k)));
      },
      registerCertificate: function(certificate) {
        this.__notify('registerCertificate', certificate);
      },
      raiseProvisioningFailure: function(reason) {
        this.__notify("raiseProvisioningFailure",
                      reason);
      },
      _primaryAPIIsShimmed: true,
      __post: function(msg, force) {
        if (!this.__ready && !force) {
          dump("Queuing: " + JSON.stringify(msg));
          this.__queue.push(msg);
          return;
        }
        let data = {}
        for (let [k, v] in Iterator(msg)) data[k] = v;
        data.method = "vep_prov::" + msg.method;
        dump("Posting: " + JSON.stringify(data));
        window.parent.postMessage(JSON.stringify(data),
                                  document.documentElement.getAttribute("shimServer"));
      },
      __call: function(method, success, params) {
        let id = this.__transId++;
        this.__callbacks[id] = success;
        this.__post({id: id, method: method, params: params});
      },
      __notify: function(method, params) {
        this.__post({method: method, params: params});
      },
      __ready: false,
      __transId: 1,
      __callbacks: {},
      __queue: [],
    };
    window.addEventListener("message", function(event) {
      if (event.origin != document.documentElement.getAttribute("shimServer")) {
        return; // not from shim API
      }
      dump("Got message: " + event.data);
      let data = JSON.parse(event.data);
      switch (data.method) {
        case "vep_prov::__ready": {
          navigator.id.__ready = true;
          while (navigator.id.__queue.length > 0) {
            navigator.id.__post(navigator.id.__queue.pop());
          }
          break;
        }
        case undefined: {
          if (data.id in navigator.id.__callbacks) {
            navigator.id.__callbacks[data.id](data.result);
          }
          break;
        }
      }
    }, false);
    navigator.id.__post({method: "__ready", params: "ping"}, true);
  }
})();