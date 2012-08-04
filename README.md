BrowserIdP
==========

== Overview
BrowserIdP is an experimental stab at implementing a https://www.persona.org/[Mozilla Persona] https://developer.mozilla.org/en-US/docs/BrowserID/Guide_to_Implementing_a_Persona_IdP[Identity Provider] as a Firefox extension.  Note that it does some unsafe things; for example, it can cause crashes if you attempt to quit while it's off doing things.

== Using the extension
. Install a Firefox from the https://tbpl.mozilla.org/?tree=Pine[pine] branch (until the native UI https://bugzilla.mozilla.org/show_bug.cgi?id=764213[lands] in mozilla-central)
. Install the extension (pack it up in an https://developer.mozilla.org/en-US/docs/Bundles[XPI], or using a https://developer.mozilla.org/en-US/docs/Setting_up_extension_development_environment#Firefox_extension_proxy_file[proxy file]).
. Go to addon options, and click on the _Generate_ button
. Enter the your hostname when prompted (i.e. the part after @ in your desired identities)
. Click on _Copy JSON_ after a key has been generated
. Upload the contents of your clipboard as +/.well-known/browserid+ on your server (i.e. +https://hostname/.well-known/browserid+)
. Login to a Persona-based site (currently supporting the dev branch, test with http://dev.123done.org/)

The keys are stored in the Firefox/Gecko Login Manager; filter for "x-browseridp:" in your saved passwords to see them.

== Known issues
These should go into the github issues list, but in the mean time...

- Need to do the NSS shutdown lock stuff (i.e. will probably crash on shutdown if it's attempting to process something)
- Implement key export
- Implement key import
