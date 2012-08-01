const EXPORTED_SYMBOLS = ["Options"];

const { classes: Cc, interfaces: Ci, utils: Cu } = Components;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");

function getString(doc, key) {
    let template = doc.querySelector("#detail-rows > setting[data-id='template']");
    return template.getAttribute("data-" + key);
}

const Options = {
    startup: function Options_startup(data) {
        this.addonData = data;
        Services.obs.addObserver(this, "addon-options-displayed", false);
        Services.obs.addObserver(this, "addon-options-hidden", false);
    },
    shutdown: function Options_shutdown() {
        Services.obs.removeObserver(this, "addon-options-displayed", false);
        Services.obs.removeObserver(this, "addon-options-hidden", false);
        delete this.addonData;
    },
    observe: function Options_observe(subject, topic, data) {
        let funcName = ("on-" + topic).replace(/-(.)/g, function(r) r[1].toUpperCase());
        if (/^addon-options-/.test(topic) && funcName in this) {
            if (data == this.addonData.id) {
                this[funcName](subject);
            }
        }
    },
    onGenerate: function Options_onGenerate(event) {
        let doc = event.target.ownerDocument;
        let container = doc.querySelector("#detail-rows > setting[data-id='setting-global']");
        container.querySelector("button[data-id='cmdGenerate']").collapsed = true;
        container.querySelector("button[data-id='cmdGenerateBusy']").collapsed = false;
        function cleanup() {
            container.querySelector("button[data-id='cmdGenerate']").collapsed = false;
            container.querySelector("button[data-id='cmdGenerateBusy']").collapsed = true;
        }
        var host = undefined, result = null;
        function accept() {
            let oldLogins = Services.logins.findLogins({}, "x-browseridp:",
                                                       null, host);
            if (oldLogins.length) {
                var bag = Cc["@mozilla.org/hash-property-bag;1"]
                            .createInstance(Ci.nsIWritablePropertyBag2);
                bag.setPropertyAsAString("username", JSON.stringify(result.pubkey));
                bag.setPropertyAsAString("password", JSON.stringify(result.privateKey));
                Services.logins.modifyLogin(oldLogins[0], bag);
            } else {
                let login = Cc["@mozilla.org/login-manager/loginInfo;1"]
                              .createInstance(Ci.nsILoginInfo);
                login.init("x-browseridp:",
                           null, host,
                           JSON.stringify(result.pubkey),
                           JSON.stringify(result.privateKey),
                           "", "");
                Services.logins.addLogin(login);
            }
            // redraw the whole page to show the new domain
            Services.tm.currentThread.dispatch(function() {
                Options.onAddonOptionsHidden(doc);
                Options.onAddonOptionsDisplayed(doc);
            }, Ci.nsIEventTarget.DISPATCH_NORMAL);
        }
        try {
            var worker = ChromeWorker("chrome://browseridp/content/crypto.js?" + Date.now());
            worker.onmessage = function(event) {
                try {
                    if (("rv" in event.data) && event.data.rv) {
                        Cu.reportError(event.data.rv + ": " + String(event.data.message));
                        return;
                    }
                    result = event.data;
                    if (host !== undefined) {
                        if (host) {
                            accept();
                        }
                        cleanup();
                    }
                } catch (ex) {
                    Cu.reportError(ex);
                }
            }
            worker.postMessage({command: "generate",
                                alg: "RS256"});
            let hostBuffer = {value: null};
            var rv = Services.prompt.prompt(doc.defaultView,
                                            getString(doc, "generate-prompt-title"),
                                            getString(doc, "generate-prompt-text"),
                                            hostBuffer, null, {value: false});
            host = !rv ? null : hostBuffer.value;
            if (result !== null) {
                accept();
                cleanup();
            }
        } catch (ex) {
            Cu.reportError(ex);
            cleanup();
        }
    },
    onJSON: function Options_onJSON(event) {
        let setting = event.target;
        while (setting && setting.localName != "setting") {
            setting = setting.parentNode;
        }
        if (!setting) return;
        let doc = setting.ownerDocument;
        let host = setting.getAttribute("data-host");
        if (!host) return;
        let logins = Services.logins.findLogins({}, "x-browseridp:",
                                                null, host);
        if (logins.length < 1) return;
        let login = logins[0];
        let pubkey = JSON.parse(login.username);
        let params = {
            "public-key": pubkey,
            "authentication": "chrome://browseridp/content/sign_in.html",
            "provisioning": "chrome:///browserido/content/provision.html",
        };
        for (let [k, v] in Iterator({
            "version": "2012.08.15",
            // the mozilla browserid impl appears to use standard base64,
            // not base64url...
            "modulus": (pubkey.mod || "").replace(/-/g, "+").replace(/_/g, "/"),
            "exponent": (pubkey.exp || "").replace(/-/g, "+").replace(/_/g, "/"),
        })) {
            params["public-key"][k] = v;
        }
        Cc["@mozilla.org/widget/clipboardhelper;1"]
          .getService(Ci.nsIClipboardHelper)
          .copyString(JSON.stringify(params), event.target.ownerDocument);
    },
    onDelete: function Options_onDelete(event) {
        let setting = event.target;
        while (setting && setting.localName != "setting") {
            setting = setting.parentNode;
        }
        if (!setting) return;
        let doc = setting.ownerDocument;
        let host = setting.getAttribute("data-host");
        if (!host) return;
        let logins = Services.logins.findLogins({}, "x-browseridp:",
                                                null, host);
        if (logins.length) {
            Services.logins.removeLogin(logins[0]);
        }
        Services.tm.currentThread.dispatch(function() {
            Options.onAddonOptionsHidden(doc);
            Options.onAddonOptionsDisplayed(doc);
        }, Ci.nsIEventTarget.DISPATCH_NORMAL);
    },
    onAddonOptionsDisplayed: function Options_onAddonOptionsDisplayed(doc) {
        let logins = Services.logins.findLogins({}, "x-browseridp:",
                                                null, "")
                             .sort(function(a, b) a.httpRealm.localeCompare(b.httpRealm));
        for each (let login in logins) {
            let setting = doc.createElement("setting");
            setting.setAttribute("data-host", login.httpRealm);
            setting.setAttribute("title", login.httpRealm);
            setting.setAttribute("type", "control");
            doc.getElementById("detail-rows").appendChild(setting);
            let cmdJSON = doc.createElement("button");
            cmdJSON.setAttribute("data-id", "cmdJSON");
            cmdJSON.setAttribute("label", getString(doc, "json-label"));
            cmdJSON.setAttribute("tooltiptext", getString(doc, "json-tooltiptext"));
            setting.appendChild(cmdJSON);
            cmdJSON.addEventListener("command", Options.onJSON, false);
            let cmdExport = doc.createElement("button");
            cmdExport.setAttribute("data-id", "cmdExport");
            cmdExport.setAttribute("label", getString(doc, "export-label"));
            cmdExport.setAttribute("tooltiptext", getString(doc, "export-tooltiptext"));
            setting.appendChild(cmdExport);
            let cmdDelete = doc.createElement("button");
            cmdDelete.setAttribute("data-id", "cmdDelete");
            cmdDelete.setAttribute("label", getString(doc, "delete-label"));
            cmdDelete.setAttribute("tooltiptext", getString(doc, "delete-tooltiptext"));
            setting.appendChild(cmdDelete);
            cmdDelete.addEventListener("command", Options.onDelete, false);
        }
        doc.querySelector("#detail-rows > setting[data-id='setting-global'] > button[data-id='cmdGenerate']")
           .addEventListener("command", this.onGenerate, false);
    },
    onAddonOptionsHidden: function Options_onAddonOptionsHidden(doc) {
        let settings = doc.querySelectorAll("#detail-rows > setting[data-host]");
        for each (let setting in Array.slice(settings)) {
            for (let [id, handler] in Iterator({
                "cmdJSON": Options.onJSON,
                "cmdDelete": Options.onDelete,
            })) {
                setting.querySelector("[data-id='" + id + "']").removeEventListener("command", handler);
            }
            setting.parentNode.removeChild(setting);
        }
        doc.querySelector("#detail-rows > setting[data-id='setting-global'] > button[data-id='cmdGenerate']")
           .removeEventListener("command", this.onGenerate);
    },
    QueryInterface: XPCOMUtils.generateQI([Ci.nsIObserver]),
};
