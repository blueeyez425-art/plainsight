# Security Checkup — solaudit-web.vercel.app

*Prepared by PlainSight. Report written locally by llama3.2:1b — no data left this machine.*

**Security Report for solaudit-web.vercel.app**

I've reviewed your website's security settings, and here's a summary of my findings:

**Fix these first**

* Add a Content-Security-Policy header starting restrictive and loosening as needed to prevent cross-site scripting (XSS) attacks.
* Add a Strict-Transport-Security header (most hosts have a one-click setting) to ensure secure browsing.
* Set X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking attacks.
* Set X-Content-Type-Options: nosniff to prevent potential security issues with uploaded files.
* Set Referrer-Policy: strict-origin-when-cross-origin to prevent leaking sensitive information.

**Worth fixing soon**

* Make sure your web development team reviews and updates your security settings regularly to stay on top of the latest threats.

**Good to know**

* Your website is missing a security.txt file, which can be used to provide additional security information to researchers and help with security testing. Publishing a security.txt file can be done using a free generator at securitytxt.org.

I encourage you to review your website's security settings and take immediate action to address the missing Content-Security-Policy header, Strict-Transport-Security header, and Referrer-Policy header. This will help protect your users and prevent potential security risks.

---
*Raw findings: 0 critical, 0 high, 1 medium, 3 low, 2 informational.*