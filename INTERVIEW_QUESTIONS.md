# 📚 Top 50 Cybersecurity Interview Questions & Answers

**Prepared during Elevate Labs Cybersecurity Internship**  
**Project Phase – December 2025**  
**Project #4: Password Strength Analyzer with Custom Wordlist Generator**

These are the exact **Top 50 Interview Questions** provided in the Elevate Labs internship document, along with clear, concise, and accurate answers. Perfect for quick revision and interview preparation.

---

1. **What is cybersecurity and why is it important?**  
   Cybersecurity is the practice of protecting systems, networks, programs, and data from digital attacks, unauthorized access, or damage.  
   It is important because breaches cause financial loss, data theft, reputational damage, and disruption of critical services.

2. **What’s the difference between a threat, a vulnerability, and a risk?**  
   - **Threat**: Potential danger that could exploit a weakness (e.g., hacker, malware).  
   - **Vulnerability**: A flaw or weakness in a system (e.g., unpatched software).  
   - **Risk**: The potential loss when a threat exploits a vulnerability (Risk = Likelihood × Impact).

3. **Define CIA triad (Confidentiality, Integrity, Availability).**  
   - **Confidentiality**: Only authorized people can access data (e.g., encryption).  
   - **Integrity**: Data is accurate and not altered (e.g., hashing).  
   - **Availability**: Data/systems are accessible when needed (e.g., DDoS protection).

4. **What is the difference between IDS and IPS?**  
   - **IDS**: Monitors traffic and alerts on suspicious activity (passive).  
   - **IPS**: Monitors and actively blocks suspicious activity (active).

5. **What is the difference between symmetric and asymmetric encryption?**  
   - **Symmetric**: Single shared key (faster, e.g., AES).  
   - **Asymmetric**: Public-private key pair (secure key exchange, e.g., RSA).

6. **What is the principle of least privilege?**  
   Grant only the minimum permissions required — limits damage if compromised.

7. **Explain the difference between hashing and encryption.**  
   - **Hashing**: One-way, irreversible (used for integrity/password storage).  
   - **Encryption**: Two-way, reversible with key (used for confidentiality).

8. **What is two-factor authentication (2FA) and how does it work?**  
   Requires two verification factors (e.g., password + OTP). Adds security beyond just passwords.

9. **What is the difference between black hat, white hat, and grey hat hackers?**  
   - **Black hat**: Malicious for gain/harm.  
   - **White hat**: Ethical, tests with permission.  
   - **Grey hat**: Unauthorized but discloses findings.

10. **What are some common cyber attack vectors?**  
    Phishing, malware, weak passwords, unpatched software, social engineering, insider threats.

11. **What is a firewall and how does it work?**  
    Monitors and controls traffic based on rules (allows/blocks by IP, port, protocol).

12. **What is a DMZ in network security?**  
    Separate segment for public-facing servers to protect the internal network.

13. **What are the different types of firewalls?**  
    Packet filtering, stateful, proxy, next-generation (NGFW), application-level.

14. **What is port scanning and how is it used in cyber attacks?**  
    Scanning for open ports/services — used in reconnaissance to find exploitable entry points.

15. **What is ARP poisoning and how can it be prevented?**  
    Spoofing MAC-IP mapping for MITM. Prevention: Static ARP, detection tools, port security.

16. **What are TCP and UDP? How do they differ in security context?**  
    TCP: Reliable, connection-oriented. UDP: Fast, connectionless. UDP often used in DDoS amplification.

17. **What is VPN and how does it ensure secure communication?**  
    Encrypted tunnel over public networks using protocols like IPsec/OpenVPN.

18. **What is MAC flooding?**  
    Overloading switch MAC table to force hub-like behavior → enables sniffing.

19. **How do you secure a Wi-Fi network?**  
    WPA3/WPA2, strong passphrase, disable WPS, firmware updates, guest network isolation.

20. **What are the roles of SSL/TLS in network security?**  
    Encryption, authentication (certificates), and integrity for data in transit (HTTPS).

21. **What is OS hardening? Name a few techniques.**  
    Reducing attack surface: Disable unused services, strong passwords, patching, firewall.

22. **What is a rootkit and how does it work?**  
    Malware that hides itself and provides privileged access by modifying kernel/system.

23. **What is patch management and why is it important?**  
    Applying updates to fix vulnerabilities — prevents known exploits.

24. **How do you secure a Linux server?**  
    SSH keys, disable root login, firewall, updates, fail2ban, SELinux/AppArmor.

25. **What is privilege escalation and how can it be prevented?**  
    Gaining higher access. Prevention: Least privilege, patching, monitoring.

26. **What are some tools to monitor system logs and detect anomalies?**  
    Syslog, journalctl, ELK Stack, Splunk, OSSEC, Fail2Ban.

27. **What is the Windows Security Event Log and what are key events to monitor?**  
    Records security events. Key: 4624/4625 (logons), 4648 (run as), 1102 (log clear).

28. **What are secure coding practices to prevent vulnerabilities?**  
    Input validation, parameterized queries, least privilege, code reviews.

29. **What is sandboxing in cybersecurity?**  
    Isolating untrusted code in restricted environment.

30. **How would you protect an application from SQL Injection?**  
    Parameterized queries, input validation, stored procedures, ORM.

31. **What is a zero-day vulnerability?**  
    Unknown flaw with no patch available — highly dangerous.

32. **What is ransomware? How do you prevent it?**  
    Encrypts files for ransom. Prevention: Backups, patching, anti-malware, training.

33. **What is a man-in-the-middle (MITM) attack?**  
    Intercepting communication. Prevention: HTTPS, HSTS, VPN.

34. **What is Cross-Site Scripting (XSS)?**  
    Injecting scripts into web pages. Prevention: Sanitization, encoding, CSP.

35. **What is a buffer overflow attack?**  
    Overwriting memory → code execution. Prevention: Safe functions, ASLR, DEP.

36. **What are DDoS attacks and how can they be mitigated?**  
    Flooding traffic. Mitigation: CDN, rate limiting, WAF, scrubbing.

37. **What is phishing and how do you defend against it?**  
    Tricking users for credentials. Defense: Training, filtering, 2FA.

38. **What is session hijacking?**  
    Stealing session tokens. Prevention: HTTPS, Secure cookies, timeouts.

39. **What is a botnet?**  
    Network of compromised devices controlled for attacks.

40. **What are common indicators of compromise (IoCs)?**  
    Unusual traffic, unknown processes, failed logins, modified files.

41. **What are the top OWASP vulnerabilities?**  
    Broken Access Control, Cryptographic Failures, Injection, Insecure Design, Misconfiguration, Vulnerable Components, etc.

42. **What is penetration testing? How is it different from vulnerability scanning?**  
    Pen testing: Simulated exploitation. Scanning: Automated detection only.

43. **What tools do you use for penetration testing?**  
    Nmap, Metasploit, Burp Suite, Nessus, Wireshark, sqlmap.

44. **What is Wireshark and how is it used in cybersecurity?**  
    Packet analyzer for traffic inspection and anomaly detection.

45. **What is Metasploit and how does it work?**  
    Framework with exploits/payloads for testing vulnerabilities.

46. **What is Nmap and what are its common use cases?**  
    Network scanner for discovery, port scanning, OS detection.

47. **What is the difference between static and dynamic code analysis?**  
    Static: Source code review. Dynamic: Testing running app.

48. **What is a security information and event management (SIEM) system?**  
    Central log analysis for threat detection (e.g., Splunk).

49. **What is threat hunting?**  
    Proactive search for hidden threats beyond alerts.

50. **What’s the purpose of an incident response plan?**  
    Structured handling of breaches: Prepare → Detect → Contain → Eradicate → Recover → Learn.

---

**Best of luck with your interviews!** 🚀  
These answers helped me confidently explain concepts during my Elevate Labs internship.
