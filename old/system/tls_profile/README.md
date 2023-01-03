# TLS Profiles

Whenever you want use TLS in vulture configuration, you will need a "TLS profile".
TLS configuration may be use in TCP & HTTP listeners and in HTTP backend.

From the [Add an entry](/system/tls_profile/edit/) menu you may create additional TLS profiles

## List of TLS Profiles

### Name

This is the friendly name of the TLS Profile

### Certificate

This is the friendly name of the X509 certificate that will be presented when using this TLS profile

### Protocols

Here you can see the activated protocols within the TLS profile. Supported protocols are SSLv3 and TLSv1 (legacy, insecure, do not use !), TLSv1.1, TLSv1.2 and TLSv1.3. Use TLSv1.3 only whenever possible.

### Verify Client

When the TLS profile is associated to a TCP/HTTP listener, you may enforce the client to present a valid, trusted, X509 certificate. If verify client is set to "required": the client MUST present a valid/trusted certificate. If verify client is set to "optional": the client MAY present a valid/trusted certificate.

### Client CA

Whenever the verify client is set to "optional" or "required", here you will see the Friendly name of the *X509 CA Certificate* that should be trusted.

### Action

Here you can *delete* or *clone* the TLS profile.