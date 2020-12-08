# X509 Certificates

Here you can create or import new certificates :
 * Generate a internaly-signed certificate
 * Generate a Let's encrypt certificate
 * Import an external certificate

## Generate a internaly-signed certificate

### Friendly name

This is the friendly name associated to the certificate. Vulture will reference the certificate using this name in the Web GUI.

### Common name

This corresponds to the "CN" field of the certificate you want to create
Other attributes (OU, O, C....) are copied from the Vulture internal CA and cannot be modified

## Generate a Let's encrypt certificate

### Friendly name

This is the friendly name associated to the certificate. Vulture will reference the certificate using this name in the Web GUI.

### Common name

This corresponds to the "CN" field of the certificate you want to create
Other attributes are provided automaticaly by Let's encrypt, typically: C=US, O=Let's Encrypt

## Import an external certificate

### Friendly name

This is the friendly name associated to the certificate. Vulture will reference the certificate using this name in the Web GUI.

### PEM Certificate

copy/paste your PEM certificate here

### PEM Private Key

copy/paste your PEM private key here

### PEM Certificate Chain

copy/paste your PEM certificate chain here
