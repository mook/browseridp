const EXPORTED_SYMBOLS = ["Options"];

const { utils: Cu, interfaces: Ci } = Components;

Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");

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
    onGenerate: function Options_onGenerate() {
        Cu.reportError("generate!");
        try {
        let worker = ChromeWorker("chrome://browseridp/content/crypto.js?" + Date.now());
        worker.onmessage = function(event) {
            if (("rv" in event.data) && event.data.rv) {
                Cu.reportError(event.data.message);
                return;
            }
            Cu.reportError("result: " + JSON.stringify(event.data));
        }
        worker.postMessage({command: "generate",
                            alg: "RS256"});
        } catch (ex) { Cu.reportError(ex); }
    },
    onAddonOptionsDisplayed: function Options_onAddonOptionsDisplayed(doc) {
        let logins = Services.logins.findLogins({}, "x-browseridp:",
                                                null, "")
                             .sort(function(a, b) a.httpRealm.localeCompare(b.httpRealm));
        let template = doc.querySelector("#detail-rows > setting[data-id='template']");
        for each (let login in logins) {
            let setting = doc.createElement("setting");
            setting.setAttribute("data-host", login.httpRealm);
            setting.setAttribute("title", login.httpRealm);
            setting.setAttribute("type", "control");
            doc.getElementById("detail-rows").appendChild(setting);
            let cmdExport = doc.createElement("button");
            cmdExport.setAttribute("label",
                                   template.getAttribute("data-export-label"));
            cmdExport.setAttribute("tooltiptext",
                                   template.getAttribute("data-export-tooltiptext"));
            setting.appendChild(cmdExport);
            let cmdDelete = doc.createElement("button");
            cmdDelete.setAttribute("label",
                                   template.getAttribute("data-delete-label"));
            cmdDelete.setAttribute("tooltiptext",
                                   template.getAttribute("data-delete-tooltiptext"));
            setting.appendChild(cmdDelete);
        }
        doc.querySelector("#detail-rows button[data-id='cmdGenerate']")
           .addEventListener("command", this.onGenerate);
    },
    onAddonOptionsHidden: function Options_onAddonOptionsHidden(doc) {
        let settings = document.querySelectorAll("#detail-rows > setting[data-host]");
        for each (let setting in Array.slice(settings)) {
            setting.parentNode.removeChild(settings);
        }
    },
    QueryInterface: XPCOMUtils.generateQI([Ci.nsIObserver]),
};
