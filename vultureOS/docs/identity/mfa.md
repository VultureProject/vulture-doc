# MFA & OTP - Multi-Factor Authentication and One Time Password

## Overall operation

After a succesful user authentication, Vulture may ask for an additional verification OTP code (One-time password). The OTP can be sent to the user via several channels :

 - Phone (SMS or mobile application) : This service is managed by an external web service provided by Authy (see [Twilio Authy Website](https://authy.com) to create a account).
 - Email : This service is provided by Vulture. An email will be sent to the user with the expected OTP.
 - Time-base OTP : This service is provided by Vulture, via the Python **PyOTP** package : "PyOTP is a Python library for generating and verifying one-time passwords. It can be used to implement two-factor (2FA) or multi-factor (MFA) authentication methods in web applications and in other systems that require users to log in." 

Note that these features require an access to user email and or telephone number. So, they are only compatible with LDAP repository and external IDP authentication repositories.

## Settings

`Name`: A friendly name to identify the repository. It has to be unique.

`Authentication type` :

 - **Phone**: The OTP will be sent via the configured Phone service (see below).
 - **OneTouch**: The OTP will be sent via the configured Phone service (see below).
 - **Email**: The OTP will be sent via an email, sent by the configured Mail service (see below).
 - **Time-based OTP**: The OTP will be sent via Vulture, using the **PyOTP** package : A QRCode will be displayed in the portal at first authentication attempt and the user will be able to register the OTP service using its favorite app such as Google or Microsoft Authenticator (see below). 

### Specific settings for Phone and OneTouch MFA

These OTP features are supported via an external 'Twilio / Authy' Cloud service. You need to have an valid subscription on Twilio (see [Twilio Authy Website](https://authy.com) to create a account).

`API Key`: One you have configured your Twilio/Authy services, you just have to copy/paste your API Key to benefits of the features in Vulture.


### Specific settings for Email MFA

With this mode, Vulture will send the OTP via an email to the user. 

`Mail service` : You can choose the mail service to use to end the email. For the moment only the "Vulture mail service" is available, the SMTP server relay may be configured from the [cluster settings](../global_config/cluster.md/#network-services) administration menu.

### Specific settings for Time-based OTP
