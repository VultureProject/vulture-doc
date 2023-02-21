# WebGUI - Menu "X509 Certificates"

Vulture has an internal PKI that is used for securing inter-cluster communication and Web GUI Access.
From this menu you can add and revoke certificate using this PKI.

From the **Add an entry** menu you may :

- Generate a internaly-signed certificate
- Generate a Let's encrypt certificate
- Import an external certificate

## List of registered certificates

- `Type` : Here you have the certificate type :

    - **Vulture CA** : This is the internal CA certificate
    - **Internal** : This is a certificate that has been signed by the Vulture internal CA (eg: A node certificate)
    - **Trusted CA** : This is a external CA certificate, that Vulture should trust in a TLS listener
    - **External** : This is a certificate signed by an external CA, that Vulture may use in a TLS listener or TLS client

- `Status` : Indicates if the certificate is valid or not (expired / revoked).
- `Name` : This is the friendly name of the certificate
- `Subject` : This is the full DN string of the certificate
- `Issuer` : This is the full DN string of the issuer certificate
- `Valid From` : This is the validity start date of the certificate
- `Valid Till` : This is the validity end date of the certificate
- `Action` :
    - **Download Cert** : This allows you to download the PEM certificate file
    - **Download bundle** : This allows you to download the certificate chain as well as the private key (if available) of the certificate :

        - The PEM certificate
        - The PEM key
        - The PEM certificate chain (if available)

    - **Download CRL** : For the Internal Vulture CA, you can download the Certificate Revocation List
    - **Generate CRL** : For the Intervan Vulture CA, you can force a CRL generation
    - **Revoke** : For an internaly signed certificate, you can revoke the certificate from here
    - **Remove from database** : If you want to suppress a certificate from the Vulture database, click here


## X509 Certificates

Here you can create or import new certificates :
 * Generate a internaly-signed certificate
 * Generate a Let's encrypt certificate
 * Import an external certificate

### Generate a internaly-signed certificate

- `Friendly name` : This is the friendly name associated to the certificate. Vulture will reference the certificate using this name in the Web GUI.
- `Common name` : This corresponds to the "CN" field of the certificate you want to create. Other attributes (OU, O, C....) are copied from the Vulture internal CA and cannot be modified

### Generate a Let's encrypt certificate

- `Friendly name` : This is the friendly name associated to the certificate. Vulture will reference the certificate using this name in the Web GUI.
- `Common name` : This corresponds to the "CN" field of the certificate you want to create. Other attributes are provided automaticaly by Let's encrypt, typically : C=US, O=Let's Encrypt

### Import an external certificate

- `Friendly name` : This is the friendly name associated to the certificate. Vulture will reference the certificate using this name in the Web GUI.
- `PEM Certificate` : copy/paste your PEM certificate here
- `PEM Private Key` : copy/paste your PEM private key here
- `PEM Certificate Chain` : copy/paste your PEM certificate chain here
