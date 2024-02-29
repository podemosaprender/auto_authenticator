# auto_authenticator

Simple, safe=easy to code review unattended replacement for GoogleAuthenticator e.g. if you need to use 2FA with Selenium WebDriver

1. In GoogleAuthenticator menu
   1. Transfer Accounts
   2. Export Accounts
   3. Select ONLY THE ONE account you want to export
   4. Scan the QR to get the text, e.g. with other Android Device Camera    
      _the text looks like_ `otpauth-migration://offline?data=73oiweouqw(many more chars)`
   5. **Keep this URL secret!** e.g. with linux `pass` and gnupg
2. Each time you want to generate an OTP token for this URL
~~~
OTP_URL=`pass show myhost/2faurl` python src/otp.py
~~~
  
May be used as a library too.

Adapted from and with special thanks to:
* https://github.com/jan-janssen/pyauthenticator
* https://github.com/scito/extract_otp_secrets


