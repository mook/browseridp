const EXPORTED_SYMBOLS = ["Options"];

const { classes: Cc, interfaces: Ci, utils: Cu } = Components;

Cu.import("resource://gre/modules/FileUtils.jsm");
Cu.import("resource://gre/modules/NetUtil.jsm");
Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");

function getString(doc, key, ...replacements) {
    let template = doc.querySelector("#detail-rows > setting[data-id='template']");
    let string = template.getAttribute("data-" + key) || key;
    for each (let [index, replacement] in Iterator(replacements)) {
        string = string.replace("{" + index + "}", replacement);
    }
    return string;
}

function debug(msg, ...rest) {
    const prefName = "extensions.browseridp.debug";
    if (Services.prefs.getPrefType(prefName) != Ci.nsIPrefBranch.PREF_BOOL)
        return;
    if (!Services.prefs.getBoolPref(prefName))
        return;
    Services.console.logStringMessage("BrowserIdP: " +
                                      String(msg) +
                                      rest.join(", "));
}

function error(msg, ...rest) {
    Components.utils.reportError("BrowserIdP: " +
                                 String(msg) +
                                 rest.join(", "));
}

if (typeof(atob) === "undefined") {
    Components.utils.getGlobalForObject({}).atob = function atob(str) {
        // Implement our own atob() (base64 decoder).  This should be the same
        // as ths standard one, except a lot slower.
        function doChunk(chunk) {
            const kDigits = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            chunk = chunk.replace(/=+$/, "");
            let parts = [ kDigits.indexOf(chunk[i]) for (i in chunk) ];
            let sum = parts[0] << 18 |
                      parts[1] << 12 |
                      parts[2] <<  6 |
                      parts[3] <<  0 ;
            let result = [ (sum >>> 16) & 0xFF,
                           (sum >>>  8) & 0xFF,
                           (sum >>>  0) & 0xFF ];
            return result.slice(0, chunk.length - 1);
        }
        let result = [];
        for (let i = 0; i < str.length; i += 4) {
            result.push.apply(result, doChunk(str.substr(i, i + 4)));
        }
        return result.map(function(c) String.fromCharCode(c)).join("");
    };
}

/**
 * base64-to-decimal converter, to support old-style .well-known files
 */
function base64ToDecimal(str) {
    // The digits of the result, in base 256
    const octets = new Uint8Array(atob(str).split("").map(function(c) c.charCodeAt(0)).reverse());
    //print("octets: " + [octets[i].toString(10) for (i in octets)]);
    // The maximum number of decimal digits in the result
    const length = Math.ceil(octets.length * Math.log(256) / Math.log(10));
    // The final result, expressed as BCD (little-endian)
    let result = new Uint8Array(length);
    // The upcoming power of 256, expressed as BCD (little-endian)
    let base = new Uint8Array(length);
    base[0] = 1;
    for (let i = 0; i < octets.length; ++i) {
        // The value of this (base-256) digit
        let value = new Uint8Array(base);
        // multiply base by octets[i]
        let carry = 0;
        for (let j = 0; j < length; ++j) {
            carry += value[j] * octets[i];
            value[j] = carry % 10;
            carry = (carry - value[j]) / 10;
        }
        // add the result
        carry = 0;
        for (let j = 0; j < length; ++j) {
            carry = carry + result[j] + value[j];
            result[j] = carry % 10;
            carry = (carry / 10) >>> 0;
        }
        // caclculate the next base
        carry = 0;
        for (let j = 0; j < length; ++j) {
            carry += base[j] * 256;
            base[j] = carry % 10;
            carry = (carry - base[j]) / 10;
        }
    }
    return [result[x] for (x in result)].reverse().join("").replace(/^0+/, "");
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
    refresh: function Options_refresh(doc) {
        Services.tm.currentThread.dispatch(function() {
            Options.onAddonOptionsHidden(doc);
            Options.onAddonOptionsDisplayed(doc);
        }, Ci.nsIEventTarget.DISPATCH_NORMAL);
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
            result.pubkey.kid = ["browseridp", Options.addonData.version, Date.now()].join(":");
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
            Options.refresh(doc);
        }
        try {
            var worker = ChromeWorker("chrome://browseridp/content/crypto.js?" + Date.now());
            worker.onmessage = function(event) {
                if ("log" in event.data) {
                    debug(event.data.log);
                    return;
                }
                try {
                    if (("rv" in event.data) && event.data.rv) {
                        Cu.reportError(event.data.rv + ": " + String(event.data.message));
                        return;
                    }
                    result = event.data;
                    debug("got key: " + JSON.stringify(result));
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
    onImport: function Options_onImport(event) {
        let doc = event.target.ownerDocument;
        let dirSvcKey;
        let picker = Cc["@mozilla.org/filepicker;1"].createInstance(Ci.nsIFilePicker);
        picker.init(doc.defaultView,
                    getString(doc, "import-picker-title"),
                    Ci.nsIFilePicker.modeOpen);
        picker.appendFilter(getString(doc, "picker-filter"), "*.browseridp");
        picker.defaultExtension = "browseridp";
        switch (Services.appinfo.OS) {
            case "Darwin": dirSvcKey = "Docs"; break;
            case "WINNT": dirSvcKey = "Pers"; break;
            default: dirSvcKey = "XDGDocs"; break;
        }
        try {
            picker.displayDirectory = Services.dirsvc.get(dirSvcKey, Ci.nsIFile);
        } catch (ex) {
            // ignore failure to find a useful docs directory
        }
        if (picker.show() == Ci.nsIFilePicker.returnCancel) {
            return;
        }
        if (!picker.file || !picker.file.exists()) {
            error("Import: Unexpected got missing file");
            return; // huh?
        }

        let data;
        let worker = ChromeWorker("chrome://browseridp/content/crypto.js?" + Date.now());
        worker.onmessage = function(event) {
            if ("log" in event.data) {
                debug(event.data.log);
                return;
            }
            try {
                if (("rv" in event.data) && event.data.rv) {
                    Cu.reportError(event.data.rv + ": " + String(event.data.message));
                    error(String(event.data.message));
                    return;
                }

                data.privkey = event.data.result;
                let oldLogins = Services.logins.findLogins({}, "x-browseridp:",
                                                           null, data.host);
                if (oldLogins.length) {
                    var bag = Cc["@mozilla.org/hash-property-bag;1"]
                                .createInstance(Ci.nsIWritablePropertyBag2);
                    bag.setPropertyAsAString("username", JSON.stringify(data.pubkey));
                    bag.setPropertyAsAString("password", JSON.stringify(data.privkey));
                    Services.logins.modifyLogin(oldLogins[0], bag);
                } else {
                    let login = Cc["@mozilla.org/login-manager/loginInfo;1"]
                                  .createInstance(Ci.nsILoginInfo);
                    login.init("x-browseridp:",
                               null, data.host,
                               JSON.stringify(data.pubkey),
                               JSON.stringify(data.privkey),
                               "", "");
                    Services.logins.addLogin(login);
                }
                // redraw the whole page to show the new domain
                Options.refresh(doc);
            } catch (ex) {
                Cu.reportError(ex);
            }
        }

        let channel = NetUtil.newChannel(picker.file);
        channel.contentType = "application/json";
        NetUtil.asyncFetch(channel, function(stream, status) {
            if (!Components.isSuccessCode(status)) {
                let name = [x for (x in Components.results)
                                if (Components.results[x] == status)];
                name.push(status.toString(16)); // in case of not found
                error("Import: reading " + picker.file.path + " failed with " +
                      name[0]);
                return;
            }
            let bytes = NetUtil.readInputStreamToString(stream, stream.available());
            try {
                data = JSON.parse(bytes);
            } catch (ex) {
                error("Failed to parse " + picker.file.path + ": ",
                      ex);
                return;
            }
            debug("Got input: ", JSON.stringify(data));
            for (let key of ["host", "pubkey", "privkey"]) {
                if (!(key in data) || !data[key]) {
                    error("Imported data has no " + key);
                    return;
                }
            }
            let password = {value: null};
            var rv = Services.prompt.promptPassword(doc.defaultView,
                                                    getString(doc, "import-pass-title"),
                                                    getString(doc, "import-pass-text", data.host),
                                                    password, null, {value: false});
            if (!rv) return;

            worker.postMessage({command: "encrypt",
                                publicKey: data.pubkey,
                                privateKey: data.privkey,
                                decryptPassword: password.value,
                                encryptPassword: ""});

        });

    },
    _getLoginFromEvent: function Options__getLoginFromEvent(event) {
        let setting = event.target;
        while (setting && setting.localName != "setting") {
            setting = setting.parentNode;
        }
        if (!setting) return null;
        let doc = setting.ownerDocument;
        let host = setting.getAttribute("data-host");
        if (!host) return null;
        let logins = Services.logins.findLogins({}, "x-browseridp:",
                                                null, host);
        if (logins.length < 1) return null;
        return logins[0];
    },
    onJSON: function Options_onJSON(event) {
        let login = Options._getLoginFromEvent(event);
        if (!login) return;
        let pubkey = JSON.parse(login.username);
        let params = {
            "public-key": pubkey,
            "authentication": "chrome://browseridp/content/sign_in.html",
            "provisioning": "chrome://browseridp/content/provision.html",
        };
        for (let [k, v] in Iterator({
            "version": "2012.08.15",
            // github.com/mozilla/browserid:dev seems to be expecting
            // standard bas64, instead of base64url, here.  If we don't do this
            // stupid replace, it just skips - and _ characters, making us have
            // invalid exponents and everything dies.
            "modulus": (pubkey.mod || "").replace(/-/g, "+").replace(/_/g, "/"),
            "exponent": (pubkey.exp || "").replace(/-/g, "+").replace(/_/g, "/"),
            "n": base64ToDecimal((pubkey.mod || "").replace(/-/g, "+").replace(/_/g, "/")),
            "e": base64ToDecimal((pubkey.exp || "").replace(/-/g, "+").replace(/_/g, "/")),
        })) {
            params["public-key"][k] = v;
        }
        Cc["@mozilla.org/widget/clipboardhelper;1"]
          .getService(Ci.nsIClipboardHelper)
          .copyString(JSON.stringify(params), event.target.ownerDocument);
    },

    onExport: function Options_onExport(event) {
        let doc = event.target.ownerDocument;
        let login = Options._getLoginFromEvent(event);
        if (!login) return;
        let password = {value: null};
        var rv = Services.prompt.promptPassword(doc.defaultView,
                                                getString(doc, "export-pass-title"),
                                                getString(doc, "export-pass-text", login.httpRealm),
                                                password, null, {value: false});
        if (!rv) return;
        let data = {
            host: login.httpRealm,
            pubkey: JSON.parse(login.username),
        };
        let file = null;
        let worker = ChromeWorker("chrome://browseridp/content/crypto.js?" + Date.now());
        worker.onmessage = function(event) {
            if ("log" in event.data) {
                debug(event.data.log);
                return;
            }
            try {
                if (("rv" in event.data) && event.data.rv) {
                    Cu.reportError(event.data.rv + ": " + String(event.data.message));
                    error(String(event.data.message));
                    return;
                }
                data.privkey = event.data.result;
                debug("got export data: " + JSON.stringify(data));
                if (file) {
                    accept();
                }
            } catch (ex) {
                Cu.reportError(ex);
            }
        }
        worker.postMessage({command: "encrypt",
                            publicKey: JSON.parse(login.username),
                            privateKey: JSON.parse(login.password),
                            decryptPassword: "",
                            encryptPassword: password.value});

        function accept() {
            if (!data) return;
            let outstream = FileUtils.openSafeFileOutputStream(file);
            let conv = Cc["@mozilla.org/intl/scriptableunicodeconverter"]
                         .createInstance(Ci.nsIScriptableUnicodeConverter);
            conv.charset = "UTF-8";
            let instream = conv.convertToInputStream(JSON.stringify(data));
            NetUtil.asyncCopy(instream, outstream);
            data = null;
        }

        let dirSvcKey;
        let picker = Cc["@mozilla.org/filepicker;1"].createInstance(Ci.nsIFilePicker);
        picker.init(doc.defaultView,
                    getString(doc, "export-picker-title", data.host),
                    Ci.nsIFilePicker.modeSave);
        picker.appendFilter(getString(doc, "picker-filter"), "*.browseridp");
        picker.defaultString = data.host + ".browseridp";
        picker.defaultExtension = "browseridp";
        switch (Services.appinfo.OS) {
            case "Darwin": dirSvcKey = "Docs"; break;
            case "WINNT": dirSvcKey = "Pers"; break;
            default: dirSvcKey = "XDGDocs"; break;
        }
        try {
            picker.displayDirectory = Services.dirsvc.get(dirSvcKey, Ci.nsIFile);
        } catch (ex) {
            // ignore failure to find a useful docs directory
        }
        if (picker.show() != Ci.nsIFilePicker.returnCancel) {
            file = picker.file;
            if (data.privkey) {
                accept();
            } else {
                debug("Waiting for private key...");
            }
        }
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
        Options.refresh(doc);
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
            cmdExport.addEventListener("command", Options.onExport, false);
            let cmdDelete = doc.createElement("button");
            cmdDelete.setAttribute("data-id", "cmdDelete");
            cmdDelete.setAttribute("label", getString(doc, "delete-label"));
            cmdDelete.setAttribute("tooltiptext", getString(doc, "delete-tooltiptext"));
            setting.appendChild(cmdDelete);
            cmdDelete.addEventListener("command", Options.onDelete, false);
        }
        doc.querySelector("#detail-rows > setting[data-id='setting-global'] > button[data-id='cmdGenerate']")
           .addEventListener("command", this.onGenerate, false);
        doc.querySelector("#detail-rows > setting[data-id='setting-global'] > button[data-id='cmdImport']")
           .addEventListener("command", this.onImport, false);
    },
    onAddonOptionsHidden: function Options_onAddonOptionsHidden(doc) {
        let settings = doc.querySelectorAll("#detail-rows > setting[data-host]");
        for each (let setting in Array.slice(settings)) {
            for (let [id, handler] in Iterator({
                "cmdJSON": Options.onJSON,
                "cmdExport": Options.onExport,
                "cmdDelete": Options.onDelete,
            })) {
                setting.querySelector("[data-id='" + id + "']").removeEventListener("command", handler);
            }
            setting.parentNode.removeChild(setting);
        }
        doc.querySelector("#detail-rows > setting[data-id='setting-global'] > button[data-id='cmdGenerate']")
           .removeEventListener("command", this.onGenerate);
        doc.querySelector("#detail-rows > setting[data-id='setting-global'] > button[data-id='cmdImport']")
           .removeEventListener("command", this.onImport);
    },
    QueryInterface: XPCOMUtils.generateQI([Ci.nsIObserver]),
};
