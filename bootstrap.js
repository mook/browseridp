const { utils: Cu } = Components;

function startup(data, reason) {
    load("chrome://browseridp/content/options.js");
    Options.startup(data);
    load("chrome://browseridp/content/interceptor.js");
    Interceptor.startup(data);
}

function shutdown(data, reason) {
    Options.shutdown(data);
    Interceptor.shutdown(data);
    // unload imported scripts
    if ("_urls" in load) {
        Object.keys(load._urls).forEach(function(key) {
            if (!/^:/.test(key)) {
                return;
            }
            Cu.unload(key.substr(1));
        });
    }
}

// These are unused, but shuts up warnings
function install() {}
function uninstall() {}

// Sub-script loading helper
function load(aURL) {
    if (!("_urls" in load)) {
        load._urls = {};
    }
    var urlKey = ":" + aURL;
    if (load._urls.hasOwnProperty(urlKey)) {
        Cu.unload(aURL);
    }
    Cu.import(aURL);
    load._urls[urlKey] = true;
}
