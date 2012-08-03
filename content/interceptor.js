/**
 * This file is responsible for catching the Persona auth / provision requests
 * and redirecting it to the extension-provided URLS
 */

const { classes: Cc, interfaces: Ci, utils: Cu, results: Cr } = Components;
Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");
const EXPORTED_SYMBOLS = ["Interceptor"];

const Interceptor = {
    startup: function Interceptor_startup(addonData) {
        this.addonData = addonData;
        Services.obs.addObserver(this, "http-on-modify-request", false);
    },
    shutdown: function Interceptor_shutdown() {
        Services.obs.removeObserver(this, "http-on-modify-request");
        delete this.addonData;
    },
    observe: function Interceptor_observe(subject, topic, data) {
        if (topic != "http-on-modify-request") {
            return;
        }
        if (!(subject instanceof Ci.nsIHttpChannel)) {
            return;
        }
        switch (subject.URI.path) {
            case "//chrome://browseridp/content/sign_in.html":
            case "//chrome://browseridp/content/provision.html":
                break;
            default:
                return; // Not a browseridp URL
        }
        if (subject.URI.scheme != "https") {
            return; // Be paranoid
        }
        let logins = Services.logins.findLogins({}, "x-browseridp:",
                                                null, subject.URI.host);
        if (!logins.length) {
            return; // No login known for this host
        }
        // At this point, we know this to be a browserid login we want
        try {
            let url = subject.URI.path.substr(2) + "?host=" + subject.URI.host;
            if ("redirectTo" in subject) {
                // requires bug 765934 to land
                subject.redirectTo(Services.io.newURI(url, null, null));
            } else {
                let webnav = subject.QueryInterface(Ci.nsIChannel)
                                    .notificationCallbacks
                                    .getInterface(Ci.nsILoadContext)
                                    .associatedWindow
                                    .QueryInterface(Ci.nsIInterfaceRequestor)
                                    .getInterface(Ci.nsIWebNavigation);
                subject.cancel(Cr.NS_ERROR_BINDING_ABORTED);
                Services.tm.currentThread.dispatch(function() {
                    webnav.loadURI(url,
                                   Ci.nsIWebNavigation.LOAD_FLAGS_REPLACE_HISTORY,
                                   null, // referrer
                                   null,
                                   null);
                }, 0);
            }
        } catch (ex) {
            Cu.reportError(ex);
        }
    },
    QueryInterface: XPCOMUtils.generateQI([Ci.nsIObserver]),
};
