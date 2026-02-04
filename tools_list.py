import streamlit as st
# https://docs.streamlit.io/develop/quick-reference/cheat-sheet

st.set_page_config(layout="wide")

st.subheader("Roberto's- Cybersecurity (Python and Artificial Intelligence)")
st.balloons()
st.snow()
st.toast("Loading...")
st.write("80 Cyber Tools by Roberto in Python in Ethical Hacking")
st.subheader("Cybersecurity with Machine Learning (AI) in Python................Click to see the Code..")
#greenyellow,lime,orangered,yellowgreen,deeppink,    darkmagenta,blueviolet,red, blue
links = [
    {"href": "https://github.com/web-roberto/Cybersecurity-with-MachineLearning/blob/main/4_Regresi%C3%B3n%20Lineal%20-%20Predicci%C3%B3n%20del%20coste%20de%20un%20incidente%20de%20seguridad.ipynb",
    "text": " Linear Regression - Predicting the cost of a security incident",
    "fondo": "yellowgreen" }, # 4
    {"href": "https://github.com/web-roberto/Cybersecurity-with-MachineLearning/blob/main/5_Regresi%C3%B3n%20Log%C3%ADstica%20-%20Detecci%C3%B3n%20de%20SPAM.ipynb",
    "text": " Logistic Regression - SPAM Detection",
    "fondo": "darkmagenta" }, # 5
    {"href": "https://github.com/web-roberto/Cybersecurity-with-MachineLearning/blob/main/6_Visualizaci%C3%B3n%20del%20conjunto%20de%20datos.ipynb",
    "text": "Visualization of the dataset",
    "fondo": "blue" }, # 
    {"href": "https://github.com/web-roberto/Cybersecurity-with-MachineLearning/blob/main/7_Divisi%C3%B3n%20del%20conjunto%20de%20datos.ipynb",
    "text": "Division of the data set",
    "fondo": "red" }, # 
    {"href": "https://github.com/web-roberto/Cybersecurity-with-MachineLearning/blob/main/8_Preparaci%C3%B3n%20del%20conjunto%20de%20datos.ipynb",
    "text":  "Preparing the data set",
    "fondo": "yellowgreen" }, # 
    {"href": "https://github.com/web-roberto/Cybersecurity-with-MachineLearning/blob/main/9_Creaci%C3%B3n%20de%20Transformadores%20y%20Pipelines%20personalizados.ipynb",
    "text": " Creation of custom transformers and pipelines",
    "fondo": "darkmagenta" }, # 
    {"href": "https://github.com/web-roberto/Cybersecurity-with-MachineLearning/blob/main/10_Evaluaci%C3%B3n%20de%20resultados.ipynb",
    "text": " Evaluation of results",
    "fondo": "blue" }, # 
    {"href": "https://github.com/web-roberto/Cybersecurity-with-MachineLearning/blob/main/11_Support%20Vector%20Machine%20-%20Detecci%C3%B3n%20de%20URLs%20maliciosas.ipynb",
    "text": " Support Vector Machine (SVM) - Dataset: Malicious URL Detection",
    "fondo": "red" }, # 
    {"href": "https://github.com/web-roberto/Cybersecurity-with-MachineLearning/blob/main/12_%C3%81rboles%20de%20decisi%C3%B3n%20-%20Detecci%C3%B3n%20de%20malware%20en%20Android.ipynb",
    "text": " Decision trees",
    "fondo": "yellowgreen" }, # 
    {"href": "https://github.com/web-roberto/Cybersecurity-with-MachineLearning/blob/main/13_Random%20Forests%20-%20Detecci%C3%B3n%20de%20Malware%20en%20Android.ipynb",
    "text": " Random Forest - Malware detection on Android",
    "fondo": "darkmagenta" }, # 
    {"href": "https://github.com/web-roberto/Cybersecurity-with-MachineLearning/blob/main/14_T%C3%A9cnicas%20de%20selecci%C3%B3n%20de%20caracter%C3%ADsticas.ipynb",
    "text": "Feature selection: Malware detection on Android",
    "fondo": "blue" }, # 
    {"href": "https://github.com/web-roberto/Cybersecurity-with-MachineLearning/blob/main/15_PCA%20-%20Extracci%C3%B3n%20de%20caracter%C3%ADsticas.ipynb",
    "text": "  Principal Component Analysis (PCA): Malware detection on Android",
    "fondo": "red" }, # 
    {"href": "https://github.com/web-roberto/Cybersecurity-with-MachineLearning/blob/main/16_T%C3%A9cnicas%20de%20selecci%C3%B3n%20del%20modelo.ipynb",
    "text": " Model selection: Malware detection on Android ",
    "fondo": "yellowgreen" }, # 
    {"href": "https://github.com/web-roberto/Cybersecurity-with-MachineLearning/blob/main/17_KMEANS%20-%20Detecci%C3%B3n%20de%20transacciones%20bancarias%20fraudulentas.ipynb",
    "text": "KMEANS: detection of fraudulent bank transactions",
    "fondo": "blue" }, #
    {"href": "https://github.com/web-roberto/Cybersecurity-with-MachineLearning/blob/main/18_DBSCAN%20-%20Detecci%C3%B3n%20de%20transacciones%20bancarias%20fraudulentas.ipynb",
    "text": "DBSCAN: detection of fraudulent bank transactions",
    "fondo": "blue" }, # 
    {"href": "https://github.com/web-roberto/Cybersecurity-with-MachineLearning/blob/main/19_Naive%20Bayes%20-%20Detecci%C3%B3n%20de%20SPAM.ipynb",
    "text": "Naive Bayes: Spam detection",
    "fondo": "red" }, # 
    {"href": "https://github.com/web-roberto/Cybersecurity-with-MachineLearning/blob/main/20_Distribuci%C3%B3n%20Gaussiana%20-%20Detecci%C3%B3n%20de%20transacciones%20bancarias%20fraudulentas.ipynb",
    "text": "Gaussian Distribution: detection of fraudulent bank transactions",
    "fondo": "yellowgreen" }, # 
    {"href": "https://github.com/web-roberto/Cybersecurity-with-MachineLearning/blob/main/21_Isolation%20Forest%20-%20Detecci%C3%B3n%20de%20transacciones%20bancarias%20fraudulentas.ipynb",
    "text": "Isolation Forest: detection of fraudulent bank transactions",
    "fondo": "darkmagenta" }, #    
    {"href": "https://github.com/web-roberto/Cybersecurity-with-MachineLearning/blob/main/22_Redes%20Neuronales%20Artificiales%20-%20Detecci%C3%B3n%20de%20transacciones%20bancarias%20fraudulentas.ipynb",
    "text": "Artificial Neural Networks (ANNs): detection of fraudulent bank transactions",
    "fondo": "blue" }, #   
]
for link in links:
    st.markdown(f"""<a href="{link['href']}" target="_blank">
        <button style="background-color:{link['fondo']};color:white;padding:0.5em 1em;margin:0.5em;width:100%;border:none;text-align:start;border-radius:8px;cursor:pointer;">
            {link['text']}
        </button></a>""",unsafe_allow_html=True) 
st.subheader("Tools for Defensive Cybersecurity............................")
#greenyellow,lime,orangered,yellowgreen,deeppink,    darkmagenta,blueviolet,red, blue
links = [
    {"href": "",
    "text": "TOOLS: KALI PURPLE, WIRESHARK, AWS: RDS, VPC, PFSENSE (Firewall, squidProxy (Web Proxy), clamAV), LOAD BALANCERS,WAF (Web Application Framework) Web ACL, ",
    "fondo": "yellowgreen" }, #
    {"href": "",
    "text": "TOOLS: VPLE (Vulnerable Pentesting Lab Environment), OWASP MULTILLIDAE II,VmWare Tools, Active Directory, SPLUNK (SIEM: Security Information and Event Management) ",
    "fondo": "blue" }, #
    {"href": "",
    "text": "TOOLS: Full Disk Encryption with Bitlocker and LUCKS, AUTOPSY, EASEUS BACKUP, Intrusion Detection/Prevention Systems (IDS/IPS):Security Onion 2 (Suricata, BroIDS, Wazuh, Zeek,...)",
    "fondo": "darkmagenta" }, #
    {"href": "",
    "text": "TOOLS: openVPN, CIS Benchmark (hardened images), PROWLER )Audit a cloud account using CIS in AWS), OpenEDR (Endpoint Detection and Response), OpenEDR console in the cloud:  https://www.xcitium.com/free-edr/ ",
    "fondo": "red" }, #
    {"href": "",
    "text": "TOOLS: Wazuh (Extended Detection and Response (XDR)), Aplocker (Windows) and AppArmor (Linux), TheHive (Ticketing and incident management)",
    "fondo": "blue" }, #
    {"href": "",
    "text": "TOOLS: TheHive with Cortex, Cukoo Sandbox, Nessus (automated vulnerability analysis), openVPN",
    "fondo": "red" }, #
    {"href": "",
    "text": "CRYPTOGRAPHY: symmetric, asymmetric, Caesar cipher, encryption, frequency analysis, substitution cipher, steganography, Playfair cipher, Vigenere cipher, perfect secrecy, one-time pads, stream ciphers (RC4: SSL, TLS, WEP, Kerberos and ChaCha20), block ciphers (AES, DES) ",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "ONLINE TOOLS: dcode.fr https://www.base64encode.org/ https://cryptii.com/ https://csf.tools/ https://csf.tools/ https://www.splunk.com/ https://github.com/shauntdergrigorian/splunkqueries https://youtube.com/@splunkhowto",
    "fondo": "yellowgreen" }, # 
    {"href": "",
    "text": "ONLINE TOOLS: https://pages.nist.gov/800-63-3/ https://stylesuxx.github.io/steganography/  https://proton.prot-on.com/ https://www.sealpath.com/",
    "fondo": "blue" }, # 
    {"href": "",
    "text": "ONLINE TOOLS: https://www.autopsy.com/ https://www.cisecurity.org/controls/v8 https://www.cisecurity.org/cybersecurity-tools/cis-cat-pro https://github.com/prowler-cloud/prowler ",
    "fondo": "red" }, # 
    {"href": "",
    "text": "ONLINE TOOLS:  https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon https://virustotal.com/gui/ https://strangebee.com/",
    "fondo": "blue" }, # 
    {"href": "",
    "text": "ONLINE TOOLS: https://wazuh.com/  https://docs.securityonion.net/en/2.4/index.html https://www.splunk.com/en_us/products/splunk-security-orchestration-and-automation.html",
    "fondo": "yellowgreen" }, # 
    {"href": "",
    "text": "ONLINE TOOLS: https://github.com/cuckoosandbox",
    "fondo": "red" }, # 
    {"href": "",
    "text": "SKILLS: HASH, SHA-2, RainBow Tables, Checksum, Hamming Codes, Message Authenication Code, CBC-MAC",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "SKILLS: VMWare, RC4 (SSL, TLS, WEP, Kerberos), ChaCha20, DES, AES, Diffie Hellman, RSA with OpenSSL,CFS (Cyber Security Framework)",
    "fondo": "yellowgreen" }, # 
    {"href": "",
    "text": "SKILLS: ARP, DHCP, SSL/TLS, CIDR, VLAN, DMZ, ACL, Security Groups, Port Forwarding, Anti-DoS / Anti-DDos",
    "fondo": "blue" }, # 
    {"href": "",
    "text": "SKILLS:  triple DES, ECC (Error Correcting Codes), MAC (Message Authentication Code), HMAC (Hash based MAC), aes-256-cbc-hmac-sha256 ",
    "fondo": "red" }, # 
    {"href": "",
    "text": "SKILLS: ISO 27001: Information Security Management System, ISO 27002: Code of Practice for Information Security Management",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "SKILLS: DLP (Data Loss Prevention with ManageEngine), Gardner Magic Quadrant, IRM (Information Rights Management) with PROTON and Sealpath ",
    "fondo": "red" }, # 
    {"href": "",
    "text": "SKILLS: DORA (Digital Operational Resilience Act) , Asset Inventory: CMDB (Configuration Management Database)",
    "fondo": "yellowgreen" }, # 
    {"href": "",
    "text": "SKILLS: in CDN anti-Dos Akamai and CloudFare, Zero Trus and EPM (Endpoint Privilege Management, MISP (Malware Information Sharing Platform) )",
    "fondo": "blue" }, # 
    {"href": "",
    "text": "SKILLS: Monitorizacion & Triage, Splunk integration with TheHive, NIST SP 800-61: Computer Security Incident Handling Guide, Splunk SOAR (Phantom) ",
    "fondo": "red" }, # 
    {"href": "",
    "text": "SKILLS: Threat Hunting, CVE (Common Vulnerabilities and Exposures), CVSS (Common Vulnerability Scoring System),  CPE (Common Platform Enumeration) ",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "SKILLS: digital signature with appendix, digital signature with OpenSSL, PKI (Public Key Infraestrucutre), public key certificate with OpenSSL, Digital certificates in web browsing",
    "fondo": "blue" }, # 
    {"href": "",
    "text": "SKILLS: SailPoint, Cyberark, IAM, ActiveDirectory, Cybersecurity risk analysis, Cybersecurity threat modeling: MITRE ATTCK, STRIDE, PASTA metodology",
    "fondo": "yellowgreen" }, # 
    {"href": "https://github.com/web-roberto/defensive_cyber_python/blob/main/29.Analisis_frecuencias.ipynb",
    "text": "In Python: Frequencies Analisys",
    "fondo": "red" }, # 
    {"href": "https://github.com/web-roberto/defensive_cyber_python/blob/main/38.Analisis_frecuencias_Vigenere.ipynb",
    "text": "In Python: Vingere: Frequencies Analisys",
    "fondo": "yellowgreen" }, # 
    {"href": "https://github.com/web-roberto/defensive_cyber_python/blob/main/55.ChaCha20.ipynb",
    "text": "In Python: ChaCha20",
    "fondo": "darkmagenta" }, # 
    {"href": "https://github.com/web-roberto/defensive_cyber_python/blob/main/67.AES.ipynb",
    "text": "In Python: AES",
    "fondo": "blue" }, # 
    {"href": "https://github.com/web-roberto/defensive_cyber_python/tree/main/175.Caso_practico_deteccion_anomalias",
    "text": "In Python: Anomaly Detection",
    "fondo": "red" }, #
]
for link in links:
    st.markdown(f"""<a href="{link['href']}" target="_blank">
        <button style="background-color:{link['fondo']};color:white;padding:0.5em 1em;margin:0.5em;width:100%;border:none;text-align:start;border-radius:8px;cursor:pointer;">
            {link['text']}
        </button></a>""",unsafe_allow_html=True) 
st.subheader("Tools for Cybersecutiy in ACTIVE DIRECTORY (AD)............................")
#greenyellow,lime,orangered,yellowgreen,deeppink,    darkmagenta,blueviolet,red, blue
links = [
    {"href": "",
    "text": "SKILLS: Installation and configuration of the Windows 2022 Domain Controller (DC) with AD, Group Policy (GPO) administration, gather information with AD",
    "fondo": "yellowgreen" }, # 
    {"href": "",
    "text": "SKILLS: local enumeration of SAM, remote enumeration of SAM, AD Module: remote information gathering with a remote call to the DC, NTDS Enumeration",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "SKILLS: Safety descriptors and ACLs, Identification of vulnerable ACLs, List/Exploir of vulnerable ACEs, Explotacion DCSync, Password Spraying",
    "fondo": "blue" }, # 
    {"href": "",
    "text": "SKILLS: Kerberos in AD Server DC, Enumeration of users with Kerberos Kali and Windows Server, Brute Force with Kerberos, AS-REQ Roasting, AS-REP Roasting",
    "fondo": "red" }, # 
    {"href": "",
    "text": "SKILLS: TGS-REP Roasting (Kerberoasting), LSA, NTLM the SAM database, Dumping LSSAL (credentials of active sessions) and SAM in Windows Kali",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "SKILLS: Dumping Issas and SAM on Linux, Dumping cached domain credentials (mscash), Pass The Hash with Windows/Linux, Over Pass The Hash/Pass the Key  ",
    "fondo": "red" }, # 
    {"href": "",
    "text": "SKILLS: Pass the Ticket En Powershell, ASK-TGT/TGS, Kerberos Golden Ticket, NTLM Roasting, LLMNR/NBTNS Poisoning, NTLM/SMB Relay, Token Impersonation",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "TOOLS: Powerview from PowerSploit, Impacket and RPCClient, Ldapsearch , pywerview, jxplorer, BloodHound: Information gathering and vulnerability analysis for AD ",
    "fondo": "yellowgreen" }, #
    {"href": "",
    "text": "TOOLS: Vulnerable AD (Safebuffer), Rubeus, Covenant: Post Exploitation Framework",
    "fondo": "blue" }, # 
]
for link in links:
    st.markdown(f"""<a href="{link['href']}" target="_blank">
        <button style="background-color:{link['fondo']};color:white;padding:0.5em 1em;margin:0.5em;width:100%;border:none;text-align:start;border-radius:8px;cursor:pointer;">
            {link['text']}
        </button></a>""",unsafe_allow_html=True) 

st.subheader("Tools for Ethical Hacking............................")
#greenyellow,lime,orangered,yellowgreen,deeppink,    darkmagenta,blueviolet,red, blue
links = [
    {"href": "",
    "text": "OSSTMM (Open Source Security Testing Methodology Manual) → https://www.isecom.org/OSSTMM.3.pdf",
    "fondo": "yellowgreen" }, # 
    {"href": "",
    "text": "Examples of Ethical Hacking and Security Audit reports  → https://github.com/juliocesarfort/public-pentesting-reports ",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "Passive OSINT gathering, Youtube and google dorks  → https://www.seotecnico.com/1000-comandos-busqueda-avanzada-google.html ",
    "fondo": "blue" }, # 
    {"href": "",
    "text": "Google: hacking database  → https://www.exploit-db.com/google-hacking-database,  Google Hacking  →  Boolean commands and operators ",
    "fondo": "red" }, # 
    {"href": "",
    "text": "Shodan → search the entire internet for all devices (not web pages) and look among their ports",
    "fondo": "yellowgreen" }, # 
    {"href": "",
    "text": "Censys → scans the internet daily using Zmap and Zgraph",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "Historical internet information → https://archive.org/, TheHarvester (inside Kali) → search for information about an organization or domain in many places",
    "fondo": "blue" }, # 
    {"href": "",
    "text": "Maltego inside Kali Linux → open-source intelligence (OSINT), forensics, and cybersecurity,",
    "fondo": "red" }, # 
    {"href": "",
    "text": "Recon-ng → Python-based reconnaissance (recon) and OSINT (Open Source Intelligence) framework , FOCA →  Metadata Analysis ,Netawgoffy for Kali",
    "fondo": "yellowgreen" }, # 
    {"href": "",
    "text": "CentralOps and DNSdumpster → Google recursive search, Wireshark and TCPdump → sniffers",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "Vulnerable testing environment  → Metasploitable3 (vangrad), DNSrecon and zone transfer",
    "fondo": "blue" }, # 
    {"href": "",
    "text": "Google: bug bounty hackerone  →  apps that reward you if you find vulnerabilities in their system",
    "fondo": "red" }, # 
    {"href": "",
    "text": "NMAP → discovery of hosts, ports, services, operating systems, SNB Enumeration, SNMP Enumeration",
    "fondo": "yellowgreen" }, # 
    {"href": "",
    "text": "CVE, CVSS,CPE -Common vulnerabilities and Exposures",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "Nessus → Advanced Vulnerability Analysis, Metasploit → importing the results from Nessus, Armitage →  Metasploit Graphical Interface",
    "fondo": "blue" }, # 
    {"href": "",
    "text": "Manual exploitation of host vulnerabilities, Msfvenom → Custom Payload Creation",
    "fondo": "red" }, # 
    {"href": "",
    "text": "Differences between Bridge, NAT, and Host-only modes in VMWare",
    "fondo": "yellowgreen" }, # 
    {"href": "",
    "text": "Burp Suite  →  Interception Proxy, Spidereing an Crawling with Brup Suite and skipfhish",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "SQL injection, Code injections and context, SQLmap → Blind SQL injection",
    "fondo": "blue" }, # 
    {"href": "",
    "text": "Path traversal, WebShells → malicious scripts, often written in PHP, ASP, or JSP",
    "fondo": "red" }, # 
    {"href": "",
    "text": "Unrestricted File Upload, HTML injection y Cross-Site-Scripting (XSS)",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "CSRF (Cross-Site Request Forgery) →  web security vulnerability where an attacker tricks an authenticated user's browser",
    "fondo": "yellowgreen" }, # 
    {"href": "",
    "text": "XSStrike →  tool designed to detect Cross-Site Scripting (XSS) vulnerabilities",
    "fondo": "red" }, # 
    {"href": "",
    "text": "Cookie Tampering →  the unauthorized modification or manipulation of cookies by an attacker",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "Man in the middle (MITM), Bettercap → network monitoring tool for various jobs, in particular, man-in-the-middle attacks, network sniffing, and packet manipulation.",
    "fondo": "blue" }, # 
    {"href": "",
    "text": "ARP Spoofing →  when an attacker sends fake ARP messages. ",
    "fondo": "yellowgreen" }, # 
    {"href": "",
    "text": "DNS Spoofin →  poisoning entries on a DNS server to redirect a targeted user to a malicious website under attacker control",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "Social Engineering Toolkit (SET) →  an open-source Python tool for social-engineering and penetration testing",
    "fondo": "blue" }, # 
    {"href": "",
    "text": "Advanced exploitation WINREG, Migrating Meterpreter to another process, Deletion of evidence",
    "fondo": "red" }, # 
     {"href": "",
    "text": "Polymorph → ICMP/ MQTT traffic manipulation, Binary backdoors",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "Linux and Window → Meterpreter (metasploit) para post-explotacion",
    "fondo": "blue" }, # 
    {"href": "",
    "text": "UAC Bypass (UAC stands for Use Account →  limiting software access to administrative privileges)",
    "fondo": "red" }, # 
    {"href": "",
    "text": "Memory dump with Mimikatz, Procdump and lsass.exe, Password cracking: John the Ripper and Hashcat",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "CherryTree  →  a hierarchical note taking application",
    "fondo": "yellowgreen" }, # 
    {"href": "",
    "text": "VulnHub →  https://github.com/vulhub/vulhub tr0ll1",
    "fondo": "red" }, # 
    {"href": "",
    "text": "Snort → widely used open-source IDS for detecting malicious activity on the network → port, hosts scanning",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "NMAP → Packet fragmentation, Scanning using decoys, Spoofing the attacker's identity, Attacker speed control, IPv6 scans, scanning services and OS",
    "fondo": "blue" }, # 
    {"href": "",
    "text": "Alternatives to NMAP: NAABU and NETCAT, Ultra-fast port scanning: MASSCAN",
    "fondo": "yellowgreen" }, # 
    {"href": "",
    "text": "Troll1 machine resolution, Bug Bounty → https://pentester.land/writeups/",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "Vulnhub vulnerable environment →  vple (virtual pentesting Lab Environment is a virtual machine)",
    "fondo": "blue" }, # 
    {"href": "",
    "text": "Subdomain identification → Subfinder, Sublist3r, and Subbrute",
    "fondo": "red" }, # 
    {"href": "",
    "text": "Identification of web technologies →  WhatWeb and WebAnalyze , Content identification → Dirbuster",
    "fondo": "yellowgreen" }, # 
    {"href": "",
    "text": "Gobuster → like Dirbuster but in Go and uses brute force on subdomains",
    "fondo": "blue" }, # 
    {"href": "",
    "text": "Seclists → for brute-force passwords, Vulnerability analysis → OWASP ZAP Proxy",
    "fondo": "red" }, # 
    {"href": "",
    "text": "Spidering → searches all URLs within a page,",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "SECtheBOX → Secure Development Cycle - this tool is placed within a CICD automatic check",
    "fondo": "yellowgreen" }, # 
    {"href": "",
    "text": "Nikto and Skipfish (worse than Nikto) → website vulnerability analysis",
    "fondo": "blue" }, # 
    {"href": "",
    "text": "Nuclei and Nuclei Templates are web vulnerability scanners and other tools, and they have a YAML template repository",
    "fondo": "red" }, # 
    {"href": "",
    "text": "Advanced fuzzing with ffuf, Commix Exploitation I do command Injection, Cyberchef →  regular expressions for emails,...",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "Explotation  Changeme → searches for default credentials, Gitleaks: detect leaks and search in the old commits",
    "fondo": "yellowgreen" }, # 
    {"href": "",
    "text": "coming.",
    "fondo": "blue" }, # 
    {"href": "",
    "text": "coming.",
    "fondo": "red" }, # 
    {"href": "",
    "text": "coming.",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "coming.",
    "fondo": "yellowgreen" }, # 
    {"href": "",
    "text": "coming.",
    "fondo": "blue" }, #    
    {"href": "",
    "text": "coming.",
    "fondo": "red" }, # 
    {"href": "",
    "text": "coming.",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "coming.",
    "fondo": "yellowgreen" }, # 
    {"href": "",
    "text": "coming.",
    "fondo": "blue" }, # 
    {"href": "",
    "text": "coming.",
    "fondo": "red" }, # 
    {"href": "",
    "text": "coming.",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "coming.",
    "fondo": "yellowgreen" }, # 
    {"href": "",
    "text": "coming.",
    "fondo": "blue" }, # 
        {"href": "",
    "text": "coming.",
    "fondo": "red" }, # 
    {"href": "",
    "text": "coming.",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "coming.",
    "fondo": "yellowgreen" }, # 
    {"href": "",
    "text": "coming.",
    "fondo": "blue" }, # 
]
for link in links:
    st.markdown(f"""<a href="{link['href']}" target="_blank">
        <button style="background-color:{link['fondo']};color:white;padding:0.5em 1em;margin:0.5em;width:100%;border:none;text-align:start;border-radius:8px;cursor:pointer;">
            {link['text']}
        </button></a>""",unsafe_allow_html=True) 
st.subheader("Ethical Hacking in Python..........................Click to see the Code..")
#greenyellow,lime,orangered,yellowgreen,deeppink,    darkmagenta,blueviolet,red, blue
links = [
    {"href": "https://github.com/web-roberto/cybersecurity_python/blob/main/1_1_1_hacking_buscadores_parte1/ninjadorks.py",
    "text": "Roberto's Cybersecurity Tool -> Google Hacking -> Hacking search engines",
    "fondo": "darkmagenta" }, # 1_1_1_hacking_buscadores_parte1
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/1_1_3_ejecucion_scripts_python",
    "text": "Roberto's Cybersecurity Tool -> Google Hacking -> Execution of Python Scripts",
    "fondo": "blue" }, # 1_1_3_ejecucion_scripts_python -> 40
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/1_1_4_argumentos_linea_comandos",
    "text": "Roberto's Cybersecurity Tool -> Google Hacking -> Command Line Arguments",
    "fondo": "red" }, # 1_1_4_argumentos_linea_comandos -> 41
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/1_1_5_generacion_resultados",
    "text": "Roberto's Cybersecurity Tool -> Google Hacking -> Generation of Results",
    "fondo": "yellowgreen" }, # 1_1_5_generacion_resultados -> 42
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/1_1_6_manejo_ficheros",
    "text": "Roberto's Cybersecurity Tool -> Google Hacking -> File Handling",
    "fondo": "darkmagenta" },# 1_1_6_manejo_ficheros -> 43
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/1_1_7_dorks_ia_GPT4All",
    "text": "Roberto's Cybersecurity Tool -> Google Hacking -> Dorks with AI GPT4ALL",
    "fondo": "blue" }, # 1_1_7_dorks_ia_GPT4All -> 47
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/1_1_8_dorks_ia_OpenAI_GPT4_Parte1",
    "text": "Roberto's Cybersecurity Tool -> Google Hacking with AI -> Dorks with AI from OpenAI GPT4",
    "fondo": "red" }, # 1_1_8_dorks_ia_OpenAI_GPT4_Parte1 -> 47
    {"href": "https://github.com/web-roberto/cybersecurity_python/blob/main/1_1_1_hacking_buscadores_parte1/ninjadorks.py",
    "text": "Roberto's Cybersecurity Tool  -> Google Hacking with AI -> Dorks with AI from OpenAI GPT4 -part 2",
    "fondo": "yellowgreen" }, # 1_1_9_dorks_ia_OpenAI_GPT4_Parte2 ->48
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/1_2_1_filtrado_informacion_regex",
    "text": "Roberto's Cybersecurity Tool -> Information filtering with RegEx",
    "fondo": "darkmagenta" }, # 1_2_1_filtrado_informacion_regex -> smartsearch.pyv- video 49
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/1_2_2_filtrado_informacion_IA",
    "text": "Roberto's Cybersecurity Tool -> NinjaDork and Selenium Automation",
    "fondo": "blue" },  # 
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/1_3_automatizacion_selenium",
    "text": "Roberto's Cybersecurity Tool -> Hacking with Search Engines and Selenium",
    "fondo": "red" }, #1_3_automatizacion_selenium -> 52
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/1_4_hacking_buscadores_selenium",
    "text": "Roberto's Cybersecurity Tool -> Shodan with Python - Authentication and Login Automation",
    "fondo": "yellowgreen" }, # 1_4_hacking_buscadores_selenium -> 54
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/2_1_1_shodan_python",
    "text": "Roberto's Cybersecurity Tool -> Authentication and Login Automation",
    "fondo": "darkmagenta" }, # 
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/2_1_2_auth_login_automatizado",
    "text": "Roberto's Cybersecurity Tool  -> Information filtering with AI",
    "fondo": "blue" }, #2_1_2_auth_login_automatizado -> 60 (código en doc y en github)
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/2_1_3_auth_login_selenium",
    "text": "Roberto's Cybersecurity Tool -> Selenium: Authentication and Login Automation",
    "fondo": "red" }, # 2_1_3_auth_login_selenium -> 61
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/2_1_4_multithreading_python",
    "text": "Roberto's Cybersecurity Tool -> Multithreading with Python",
    "fondo": "yellowgreen" }, # 2_1_4_multithreading_python -> 63
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/2_2_waybackmachine",
    "text": "Roberto's Cybersecurity Tool -> Waybackmachin",
    "fondo": "darkmagenta" }, # 2_2_waybackmachine
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/2_3_dns_enumeration",
    "text": "Roberto's Cybersecurity Tool -> Dns Enumeration",
    "fondo": "blue" }, # 2_3_dns_enumeration
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/2_4_whois_enumeration",
    "text": "Roberto's Cybersecurity Tool -> Whois Enumeration",
    "fondo": "red" }, #  2_4_whois_enumeration
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/2_5_ip_geolocation",
    "text": "Roberto's Cybersecurity Tool -> Ip Geolocation",
    "fondo": "yellowgreen" },  # 2_5_ip_geolocation
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/2_6_phone_geolocation",
    "text": "Roberto's Cybersecurity Tool -> Phone Geolocation",
    "fondo": "darkmagenta" }, #  2_6_phone_geolocation
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/2_7_metadata_analyzer",
    "text": "Roberto's Cybersecurity Tool -> Metadata Analyzer",
    "fondo": "blue" }, # 2_7_metadata_analyzer
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/3_1_sniffer_tshark",
    "text": "Roberto's Cybersecurity Tool -> Sniffer Tshark",
    "fondo": "red" }, # 3_1_sniffer_tshark
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/3_2_sniffer_scapy",
    "text": "Roberto's Cybersecurity Tool -> Sniffer Scapy",
    "fondo": "yellowgreen" }, # 3_2_sniffer_scapy
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/3_3_sockets",
    "text": "Roberto's Cybersecurity Tool ->  Sockets",
    "fondo": "darkmagenta" }, #  3_3_sockets
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/3_4_1_escaneo_hosts_sockets",
    "text": "Roberto's Cybersecurity Tool -> Scan of Hosts Sockets",
    "fondo": "blue" }, # 3_4_1_escaneo_hosts_sockets
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/3_4_2_escaneo_hosts_scapy",
    "text": "Roberto's Cybersecurity Tool -> Scan of Hosts Scapy",
    "fondo": "red" }, # 3_4_2_escaneo_hosts_scapy
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/3_4_3_escaneo_arp",
    "text": "Roberto's Cybersecurity Tool -> Scan ARP",
    "fondo": "yellowgreen" }, # 3_4_3_escaneo_arp
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/3_4_4_escaneo_puertos",
    "text": "Roberto's Cybersecurity Tool ->  Scan of ports",
    "fondo": "darkmagenta" }, # 3_4_4_escaneo_puerto
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/3_4_5_escaneo_servicios",
    "text": "Roberto's Cybersecurity Tool ->  Scan of Services",
    "fondo": "blue" }, #  3_4_5_escaneo_servicios
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/3_4_6_descubrimiento_recursos_red",
    "text": "Roberto's Cybersecurity Tool -> Discovery of Resources Network",
    "fondo": "red" }, # 3_4_6_descubrimiento_recursos_red
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/3_5_nmap_scanner_python",
    "text": "Roberto's Cybersecurity Tool ->  Scanner NMAP with Python",
    "fondo": "yellowgreen" }, #  3_5_nmap_scanner_python, que seria 3_4_5
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/3_6_escaneo_priorizacion_IA",
    "text": "Roberto's Cybersecurity Tool -> AI Prioritization Scanning",
    "fondo": "darkmagenta" }, #  3_6_escaneo_priorizacion_IA, que seria 3_4_6
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/4_1_beautiful_soup",
    "text": "Roberto's Cybersecurity Tool -> Beautiful Soup",
    "fondo": "blue" }, # 4_1_beautiful_soup
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/4_2_1_escaner_vulnerabilidades_CVEs",
    "text": "Roberto's Cybersecurity Tool -> Scanner of CVE Vulnerabilities",
    "fondo": "red" }, # 4_2_1_escaner_vulnerabilidades_CVEs
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/4_2_2_escaner_vulnerabilidades_CVSS",
    "text": "Roberto's Cybersecurity Tool -> Scanner of CVSS Vulnerabilities",
    "fondo": "yellowgreen" }, # 4_2_2_escaner_vulnerabilidades_CVSS
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/4_2_3_escaner_vulnerabilidades_resultados",
    "text": "Roberto's Cybersecurity Tool -> Scanner Vulnerabilities: results",
    "fondo": "darkmagenta" }, #  4_2_3_escaner_vulnerabilidades_resultados
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/4_3_1_escaner_Nessus_creacion_sesion",
    "text": "Roberto's Cybersecurity Tool -> Nessus: session creation",
    "fondo": "blue" }, # 4_3_1_escaner_Nessus_creacion_sesion
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/4_3_2_escaner_Nessus_creacion_escaneo",
    "text": "Roberto's Cybersecurity Tool -> Nessus: scannner creation",
    "fondo": "red" }, # 4_3_2_escaner_Nessus_creacion_escaneo
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/4_3_3_escaner_Nessus_resultados",
    "text": "Roberto's Cybersecurity Tool -> Nessus: Scan results",
    "fondo": "yellowgreen" }, #  4_3_3_escaner_Nessus_resultado
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/5_1_exploit_proftpd",
    "text": "Roberto's Cybersecurity Tool -> Exploit Proftpd",
    "fondo": "darkmagenta" }, # 5_1_exploit_proftpd
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/5_2_exploit_unrealircd",
    "text": "Roberto's Cybersecurity Tool -> Exploit Unrealircd",
    "fondo": "blue" }, #  5_2_exploit_unrealircd
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/5_3_tcp_reverse_shell",
    "text": "Roberto's Cybersecurity Tool -> Tcp Reverse Shell",
    "fondo": "red" }, #  5_3_tcp_reverse_shell
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/5_4_1_http_reverse_shell",
    "text": "Roberto's Cybersecurity Tool -> Http Reverse Shell",
    "fondo": "yellowgreen" }, # 5_4_1_http_reverse_shell
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/5_4_2_one_liner_IA",
    "text": "Roberto's Cybersecurity Tool -> One Liner AI",
    "fondo": "darkmagenta" }, # 5_4_2_one_liner_IA
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/5_5_https_reverse_shell",
    "text": "Roberto's Cybersecurity Tool -> Https Reverse Shell",
    "fondo": "blue" }, # 5_5_https_reverse_shell
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/5_6_1_pymetasploit_modulos_exploits",
    "text": "Roberto's Cybersecurity Tool -> Metasploit Exploit modules",
    "fondo": "red" }, #  5_6_1_pymetasploit_modulos_exploits
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/5_6_2_pymetasploit_ejecucion_exploits",
    "text": "Roberto's Cybersecurity Tool -> Pymetasploit Execution Exploits",
    "fondo": "yellowgreen" }, # 5_6_2_pymetasploit_ejecucion_exploits
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/5_6_3_pymetasploit_manejo_sesiones",
    "text": "Roberto's Cybersecurity Tool -> Pymetasploit Sessions Handling",
    "fondo": "darkmagenta" }, # 5_6_3_pymetasploit_manejo_sesiones
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/5_7_keylogger",
    "text": "Roberto's Cybersecurity Tool -> Keylogger",
    "fondo": "blue" }, # 5_7_keylogger
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/6_1_arp_spoofing",
    "text": "Roberto's Cybersecurity Tool -> ARP Spoofing",
    "fondo": "red" }, # 6_1_arp_spoofing
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/6_2_1_netfilterqueue_interceptacion",
    "text": "Roberto's Cybersecurity Tool -> Netfilterqueue Interceptation",
    "fondo": "yellowgreen" }, # 6_2_1_netfilterqueue_interceptacion
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/6_2_2_netfilterqueue_modificacion",
    "text": "Roberto's Cybersecurity Tool ->  Netfilterqueue Modification",
    "fondo": "darkmagenta" }, # 6_2_2_netfilterqueue_modificacion
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/6_3_http_interceptor",
    "text": "Roberto's Cybersecurity Tool -> Http Interceptor",
    "fondo": "blue" }, # 6_3_http_interceptor
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/6_4_dns_spoofing",
    "text": "Roberto's Cybersecurity Tool -> DNS Spooging",
    "fondo": "red" }, # 6_4_dns_spoofing
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/6_5_arp_spoofing_detector",
    "text": "Roberto's Cybersecurity Tool -> ARP Spooging Detector",
    "fondo": "yellowgreen" }, # 6_5_arp_spoofing_detector
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/6_6_ssh_brute_force",
    "text": "Roberto's Cybersecurity Tool -> SSH BRUTE FORCE",
    "fondo": "darkmagenta" }, #  6_6_ssh_brute_force
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/6_7_dhcp_listener",
    "text": "Roberto's Cybersecurity Tool -> DHCP Listener",
    "fondo": "blue" }, # 6_7_dhcp_listener
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/6_8_mac_spoofing",
    "text": "Roberto's Cybersecurity Tool -> MAC Spoofing",
    "fondo": "red" }, # 6_8_mac_spoofing
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/7_1_spidering",
    "text": "Roberto's Cybersecurity Tool -> Spidering",
    "fondo": "yellowgreen" }, # 7_1_spidering
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/7_2_1_zap_analyzer",
    "text": "Roberto's Cybersecurity Tool -> ZAP Analyzer",
    "fondo": "darkmagenta" }, # 7_2_1_zap_analyzer
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/7_2_2_zap_analisis_pasivo",
    "text": "Roberto's Cybersecurity Tool -> ZAP Passive Analysis",
    "fondo": "blue" }, # 7_2_2_zap_analisis_pasivo
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/7_2_3_zap_analisis_activo",
    "text": "Roberto's Cybersecurity Tool -> ZAP Active Analysis",
    "fondo": "red" }, # 7_2_3_zap_analisis_activo
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/7_3_autenticacion_python",
    "text": "Roberto's Cybersecurity Tool -> Autenticacion Python",
    "fondo": "yellowgreen" }, # 7_3_autenticacion_python
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/7_4_xss_scanner",
    "text": "Roberto's Cybersecurity Tool -> XSS Scanner",
    "fondo": "darkmagenta" }, # 7_4_xss_scanner
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/7_5_sqli_scanner",
    "text": "Roberto's Cybersecurity Tool -> SQLi Scanner",
    "fondo": "blue" }, # 7_5_sqli_scanner
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/7_6_subdomain_scanner",
    "text": "Roberto's Cybersecurity Tool -> Subdomain Scanner",
    "fondo": "red" }, # 7_6_subdomain_scanner
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/7_7_web_content_discovery",
    "text": "Roberto's Cybersecurity Tool -> Web Content Discorery",
    "fondo": "yellowgreen" }, # 7_7_web_content_discovery
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/7_8_brute_force_web",
    "text": "Roberto's Cybersecurity Tool -> Brute Force Web",
    "fondo": "darkmagenta" }, # 7_8_brute_force_web
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/7_9_burp_suite_python",
    "text": "Roberto's Cybersecurity Tool -> BURP Suite Python",
    "fondo": "blue" },  # 7_9_burp_suite_python
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/8_1_cracking_passwords",
    "text": "Roberto's Cybersecurity Tool -> Cracking Passwords",
    "fondo": "red" }, #  8_1_cracking_passwords
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/8_2_cracking_zip",
    "text": "Roberto's Cybersecurity Tool -> Cracking ZIP",
    "fondo": "yellowgreen" }, #  8_2_cracking_zip
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/8_3_chrome_password_decryptor",
    "text": "Roberto's Cybersecurity Tool -> Chrome Password Decryptor",
    "fondo": "darkmagenta" }, # 8_3_chrome_password_decryptor
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/8_4_wifi_password_collector",
    "text": "Roberto's Cybersecurity Tool -> WIFI Password Collector",
    "fondo": "blue" }, # 8_4_wifi_password_collector
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/8_5_1_windows_service",
    "text": "Roberto's Cybersecurity Tool -> Windows Service",
    "fondo": "red" }, # 8_5_1_windows_service
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/8_5_2_windows_service",
    "text": "Roberto's Cybersecurity Tool -> Windows Service",
    "fondo": "yellowgreen" }, # 8_5_2_windows_service
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/8_6_evasion_defensas",
    "text": "Roberto's Cybersecurity Tool -> Evasion Defenses",
    "fondo": "darkmagenta" }, #  8_6_evasion_defensas
    {"href": "https://github.com/web-roberto/cybersecurity_python/tree/main/8_7_exfiltracion_esteganografia",
    "text": "Roberto's Cybersecurity Tool -> Exfiltration Steganography",
    "fondo": "blue" }, # 8_7_exfiltracion_esteganografia
]

# col1, col2 = st.columns([6, 1], gap="small", vertical_alignment="top", border=True, width="stretch")
# with col1:
    # st.success("Roberto's Cybersecurity Tool -> Google Hacking -> Hacking search engines") # 1_1_1_hacking_buscadores_parte1
for link in links:
    st.markdown(f"""<a href="{link['href']}" target="_blank">
        <button style="background-color:{link['fondo']};color:white;padding:0.5em 1em;margin:0.5em;width:100%;border:none;text-align:start;border-radius:8px;cursor:pointer;">
            {link['text']}
        </button></a>""",unsafe_allow_html=True)


