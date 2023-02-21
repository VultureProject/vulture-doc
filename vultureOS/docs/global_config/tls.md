# WebGUI - Menu "TLS Profiles"

Whenever you want use TLS in vulture configuration, you will need a "TLS profile".
TLS configuration may be use in TCP & HTTP listeners and in HTTP backend.

From the **"Add an entry"** menu you may create additional TLS profiles.

## List of TLS Profiles

`Name` : This is the friendly name of the TLS Profile.

`Certificate` : This is the friendly name of the X509 certificate that will be presented when using this TLS profile.

`Protocols` : Here you can see the activated protocols within the TLS profile. Supported protocols are SSLv3 and TLSv1 (legacy, insecure, do not use !), TLSv1.1, TLSv1.2 and TLSv1.3. Use TLSv1.3 only whenever possible.

`Verify Client` : When the TLS profile is associated to a TCP/HTTP listener, you may enforce the client to present a valid, trusted, X509 certificate. If verify client is set to "required" : the client MUST present a valid/trusted certificate. If verify client is set to "optional" : the client MAY present a valid/trusted certificate.

`Client CA` : Whenever the verify client is set to "optional" or "required", here you will see the Friendly name of the *X509 CA Certificate* that should be trusted.

`Action` : Here you can *delete* or *clone* the TLS profile.

## TLS Profiles

Whenever you want use TLS in vulture configuration, you will need a "TLS profile".
TLS configuration may be use in TCP & HTTP listeners and in HTTP backend.

`Friendly Name` : This is the friendly name of the TLS Profile. Vulture will use this name to refer to the TLS Profile wherever in the Web GUI.

`Certificate` : This is the friendly name of the X509 certificate that will be presented when using this TLS profile.

`Browsers compatibility` :

To avoid the pain of selecting complex ciphersuite string, Vulture has packaged ready-to-use TLS ciphers list.

* Advanced (A score) : This is the best choice for security, only TLSv1.3 and TLSv1.2 are allowed, with strong ciphers
* Broad Compatibility (B score) : Same as Advanced, only TLSv1.3 and TLSv1.2 are allowed but allowing the use of less secure ciphers
* Widest Compatibility (C score) : TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3 with medium ciphers
* Legacy (D score) : TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3 with low ciphers
* Custom : Here you may choose custom TLS protocols and cipher suite

`Advertise protocol list` : This allows to configure the HAPROXY TLS ALPN extension and advertises the specified protocol list as supported on top of ALPN.

The protocol list consists in a list of protocol names, for instance : *HTTP1.1 HTTP1.0*. ALPN is required to enable HTTP/2 on an HTTP frontend.

If both HTTP/2 and HTTP/1.1 are expected to be supported, both versions can be advertised, in order of
preference, like below : *HTTP2 HTTP1.1*

`Verify client certificate` : When the TLS profile is associated to a TCP/HTTP listener, you may enforce the client to present a valid, trusted, X509 certificate. If verify client is set to "required" : the client MUST present a valid/trusted certificate. If verify client is set to "optional": the client MAY present a valid/trusted certificate.

If set to "no" : No client certificate are expected / prompted by Vulture.

`Client CA` : Whenever the verify client is set to "optional" or "required", you have to select here the *X509 CA Certificate* that should be trusted.
