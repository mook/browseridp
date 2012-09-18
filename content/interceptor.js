/**
 * This file is responsible for catching the Persona auth / provision requests
 * and redirecting it to the extension-provided URLS
 */

const { classes: Cc, interfaces: Ci, utils: Cu, results: Cr } = Components;
Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");
Cu.import("resource://gre/modules/NetUtil.jsm");
const EXPORTED_SYMBOLS = ["Interceptor"];

function debug(msg) {
  const prefName = "extensions.browseridp.debug";
  if (Services.prefs.getPrefType(prefName) != Ci.nsIPrefBranch.PREF_BOOL)
    return;
  if (!Services.prefs.getBoolPref(prefName))
    return;
  Services.console.logStringMessage("BrowserIdP:intercept: " +
                                    String(msg) +
                                    " " + Array.slice(arguments, 1).join(", "));
}

const Interceptor = {
  _pendingWindows: {}, // type: provisioning|authentication, window: Window
  startup: function Interceptor_startup(addonData) {
    this.addonData = addonData;
    Cc["@mozilla.org/docloaderservice;1"]
      .getService(Ci.nsIWebProgress)
      .addProgressListener(Interceptor,
                           Ci.nsIWebProgress.NOTIFY_STATE_WINDOW);
  },
  shutdown: function Interceptor_shutdown() {
    delete this.addonData;
    Cc["@mozilla.org/docloaderservice;1"]
      .getService(Ci.nsIWebProgress)
      .removeProgressListener(Interceptor);
  },
  onStateChange: function Interceptor_onStateChange(aWebProgress,
                                                    aRequest,
                                                    aStateFlags,
                                                    aStatus)
  {
    if (!(aStateFlags & Ci.nsIWebProgressListener.STATE_STOP) ||
        !(aRequest instanceof Ci.nsIHttpChannel) ||
        !aRequest.URI.schemeIs("https") ||
        (aWebProgress.DOMWindow.document.contentType != "application/json"))
    {
      return;
    }

    // Can't get this before the if() check above, otherwise things die :(
    const window = aWebProgress.DOMWindow;
    // Do various checks to make sure it's a URL we want to intercept
    switch (aRequest.URI.path) {
      case "/.well-known/browserid#authentication":
      case "/.well-known/browserid#provisioning":
        break;
      default:
        //debug("ignoring URL: " + subject.URI.prePath + " :: " + subject.URI.path);
        return; // Not a browseridp URL
    }
    let host = aRequest.URI.host;
    let logins = Services.logins.findLogins({}, "x-browseridp:", null, host);
    if (!logins.length) {
      debug("Found browseridp URL " + aRequest.URI.spec +
            ", but host " + host + " is not known; ignoring");
      return; // No login known for this host
    }
    // At this point, we know that aWebProgress.DOMWindow is good and the
    // load has completed; we can start injecting things into it
    let sandbox = Cu.Sandbox(window,
                             {sandboxName: "chrome://browseridp/content/sandbox",
                               sandboxPrototype: window});
    sandbox.importFunction(function dump() {
      debug(aRequest.URI.ref + ": " +
            Array.slice(arguments).join(", "));
    });

    // Check if we need the shim
    let shimURL = null;
    try {
      shimURL = Services.io.newURI(window.frameElement.ownerDocument.documentURI,
                                   null, null);
    } catch (ex) { /* ignore, this happens with native browserid */ }
    if (shimURL) {
      window.document
            .documentElement
            .setAttribute("shimServer", shimURL.prePath);
      this._inject("chrome://browseridp/content/shim.js", sandbox);
    }

    debug("Loading script",
          "chrome://browseridp/content/" + aRequest.URI.ref + ".js");
    switch (aRequest.URI.ref) {
      case "provisioning":
        sandbox.importFunction(function sign(args) {
          // Serialize args to JSON and back to make sure they're safe
          Interceptor._sign(window, JSON.parse(JSON.stringify(args)));
        });
        break;
    }
    this._inject("chrome://browseridp/content/" + aRequest.URI.ref + ".js",
                 sandbox,
                 function()
                  Cu.evalInSandbox("start()", sandbox, "1.8",
                                   "chrome://browseridp/content/" +
                                   aRequest.URI.ref + ".js#start"));
  },
  onProgressChange: function Interceptor_onProgressChange() undefined,
  onLocationChange: function Interceptor_onLocationChange() undefined,
  onStatusChange: function Interceptor_onStatusChange() undefined,
  onSecurityChange: function Interceptor_onSecurityChange() undefined,
  /**
   * Injec the given script into the sandbox
   * @param url {String} The URL to inject
   * @param sandbox {Sandbox} The sandbox to inject to
   */
  _inject: function Interceptor__inject(url, sandbox, callback) {
    NetUtil.asyncFetch(url, function(inputStream, status) {
      if (!Components.isSuccessCode(status)) {
        return;
      }
      let script = NetUtil.readInputStreamToString(inputStream,
                                                   inputStream.available());
      Cu.evalInSandbox(script, sandbox, "1.8", url);
      if (callback) {
        callback();
      }
    });
  },
  _sign: function Interceptor__sign(window, args) {
    debug("sign: email=" + args.email + " expiry=" + args.expiry +
          " pubkey=" + JSON.stringify(args.pubkey));

    let host = String(args.email).replace(/^.*@/, "");
    let logins = Services.logins.findLogins({}, "x-browseridp:",
                                            null, host);
    if (!logins.length) {
      // host not available
      this.postToChild(window, "raiseProvisioningFailure",
                       "BrowserIdP cannot provision for host " + host);
      return;
    }
    let login = logins[0];

    // refuse to issue certs longer than 10 minutes
    let cert_expiry = Math.min(args.expiry, Date.now() + 10 * 60 * 1000);

    let header = {"typ": "JWT", "alg": "RS256"};
    let payload = {"iss": host,
                   "exp": cert_expiry,
                   "public-key": args.pubkey,
                   "principal": {
                      "email": args.email,
                   }
                  };
    debug("payload:" + JSON.stringify(payload));
    let data = [header, payload]
                .map(JSON.stringify)
                .map(function(str) btoa(unescape(encodeURIComponent(str))).replace(/=+$/,""))
                .join(".");

    var worker = ChromeWorker("chrome://browseridp/content/crypto.js");
    worker.onmessage = function(event) {
      try {
        if ("log" in event.data) {
          debug(event.data.log);
          return;
        }
        if (("rv" in event.data) && event.data.rv) {
          debug(event.data.rv + ": " + String(event.data.message));
          Interceptor.postToChild(window, "raiseProvisioningFailure",
                                  "Failed to provision: rv=" + event.data.rv +
                                  ", message: " + String(event.data.message));
          return;
        }
        let result = [data,
                      event.data.signature.replace(/=+$/, "")];
        debug('got cert: ' + JSON.stringify(event.data));
        Interceptor.postToChild(window, "registerCertificate",
                                result.join("."));
      } catch (ex) {
        Interceptor.postToChild(window, "raiseProvisioningFailure",
                                "Failed to provision: exception " + String(ex));
        Cu.reportError(ex);
      }
    }
    worker.postMessage({command: "sign",
                        data: data,
                        pubkey: JSON.parse(login.username),
                        privkey: JSON.parse(login.password),
                       });
  },
  postToChild: function Interceptor_postToChild(window, method) {
    window.postMessage({command: method,
                        origin: "browseridp-host",
                        args: Array.slice(arguments, 2)},
                       "*");

  },
  QueryInterface: XPCOMUtils.generateQI([Ci.nsIObserver,
                                         Ci.nsIWebProgressListener,
                                         Ci.nsISupportsWeakReference]),
};
