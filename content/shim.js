(function() {
  if (navigator.id) {
    return; // native implementation available
  }
  dump("navigator.id not available; using shim implementation...");

  const shimServer = document.documentElement.getAttribute("shimServer");
  document.documentElement.removeAttribute("shimServer");

  let ready = false;
  let transId = 1;
  let callbacks = {};
  let queue = [];

  function post(msg, force) {
    if (!ready && !force) {
      dump("Queuing: " + JSON.stringify(msg));
      queue.push(msg);
      return;
    }
    let data = {}
    for (let [k, v] in Iterator(msg)) data[k] = v;
    data.method = "vep_prov::" + msg.method;
    dump("Posting: " + JSON.stringify(data));
    window.parent.postMessage(JSON.stringify(data), shimServer);
  }
  function call(method, success, params) {
    let id = transId++;
    callbacks[id] = success;
    post({id: id, method: method, params: params});
  }
  function notify(method, params) {
    post({method: method, params: params});
  }


  navigator.id = {
    beginProvisioning: function(cb) {
      if (typeof cb !== 'function') {
        throw ".beginProvisioning() requires a callback argument";
      }
      call("beginProvisioning",
           function(r) {
             cb(r.email, r.cert_duration_s);
           });
    },
    genKeyPair: function(cb) {
      if (typeof cb !== 'function') {
        throw ".genKeyPair() requires a callback argument";
      }
      call("genKeyPair", function(k) cb(JSON.parse(k)));
    },
    registerCertificate: function(certificate) {
      notify('registerCertificate', certificate);
    },
    raiseProvisioningFailure: function(reason) {
      notify("raiseProvisioningFailure", reason);
    },
    _primaryAPIIsShimmed: true,
  };
  window.addEventListener("message", function(event) {
    if (event.origin != shimServer) {
      return; // not from shim API
    }
    dump("Got message: " + event.data);
    let data = JSON.parse(event.data);
    switch (data.method) {
      case "vep_prov::__ready": {
        ready = true;
        while (queue.length > 0) {
          post(queue.pop());
        }
        break;
      }
      case undefined: {
        if (data.id in callbacks) {
          callbacks[data.id](data.result);
          delete callbacks[data.id];
        }
        break;
      }
    }
  }, false);
  post({method: "__ready", params: "ping"}, true);
})();
