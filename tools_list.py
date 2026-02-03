import streamlit as st
# https://docs.streamlit.io/develop/quick-reference/cheat-sheet

st.set_page_config(layout="wide")

st.subheader("Roberto's- Cybersecurity (Python and Artificial Intelligence)")
st.balloons()
st.snow()
st.toast("Loading...")
st.write("80 Cyber Tools by Roberto in Python in Ethical Hacking")
st.subheader("Tools for Defensive Cybersecurity............................")
#greenyellow,lime,orangered,yellowgreen,deeppink,    darkmagenta,blueviolet,red, blue
links = [
    {"href": "",
    "text": "TOOLS: KALI PURPLE, WIRESHARK, AWS: RDS, VPC, PFSENSE (Firewall), LOAD BALANCERS,WAF (Web Application Framework) Web ACL, ",
    "fondo": "yellowgreen" }, #
    {"href": "",
    "text": "TOOLS: VPLE (Vulnerable Pentesting Lab Environment), OWASP MULTILLIDAE II,VmWare Tools, Active Directory ",
    "fondo": "blue" }, #
    {"href": "",
    "text": "TOOLS: Full Disk Encryption with Bitlocker and LUCKS, AUTOPSY, EASEUS BACKUP, ",
    "fondo": "red" }, #
    {"href": "",
    "text": "CRYPTOGRAPHY: symmetric, asymmetric, Caesar cipher, encryption, frequency analysis, substitution cipher, steganography, Playfair cipher, Vigenere cipher, perfect secrecy, one-time pads, stream ciphers (RC4: SSL, TLS, WEP, Kerberos and ChaCha20), block ciphers (AES, DES) ",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "ONLINE TOOLS: dcode.fr https://www.base64encode.org/ https://cryptii.com/ https://csf.tools/ https://csf.tools/",
    "fondo": "yellowgreen" }, # 
    {"href": "",
    "text": "ONLINE TOOLS: https://pages.nist.gov/800-63-3/ https://stylesuxx.github.io/steganography/  https://proton.prot-on.com/ https://www.sealpath.com/",
    "fondo": "blue" }, # 
    {"href": "",
    "text": "ONLINE TOOLS: https://www.autopsy.com/ ",
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
    "fondo": "yellowgreen" }, # 
    {"href": "",
    "text": "SKILLS: DORA (Digital Operational Resilience Act) , Asset Inventory: CMDB (Configuration Management Database)",
    "fondo": "darkmagenta" }, # 
    {"href": "https://github.com/web-roberto/defensive_cyber_python/blob/main/29.Analisis_frecuencias.ipynb",
    "text": "In Python: Frequencies Analisys",
    "fondo": "red" }, # 
    {"href": "https://github.com/web-roberto/defensive_cyber_python/blob/main/38.Analisis_frecuencias_Vigenere.ipynb",
    "text": "In Python: Vingere: Frequencies Analisys...code in Python",
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
st.subheader("Tools for Cybersecutiy in ACTIVE DIRECTORY............................")
#greenyellow,lime,orangered,yellowgreen,deeppink,    darkmagenta,blueviolet,red, blue
links = [
   {"href": "",
    "text": "N8N",
    "fondo": "yellowgreen" }, # 
    {"href": "",
    "text": "N8N",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "N8N",
    "fondo": "blue" }, # 
    {"href": "",
    "text": "N8N",
    "fondo": "red" }, # 
]
for link in links:
    st.markdown(f"""<a href="{link['href']}" target="_blank">
        <button style="background-color:{link['fondo']};color:white;padding:0.5em 1em;margin:0.5em;width:100%;border:none;text-align:start;border-radius:8px;cursor:pointer;">
            {link['text']}
        </button></a>""",unsafe_allow_html=True) 
st.subheader("Cybersecurity with AI in Python................Click to see the Code..")
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
st.subheader("Tools for Ethical Hacking............................")
#greenyellow,lime,orangered,yellowgreen,deeppink,    darkmagenta,blueviolet,red, blue
links = [
   {"href": "",
    "text": "N8N",
    "fondo": "yellowgreen" }, # 
    {"href": "",
    "text": "N8N",
    "fondo": "darkmagenta" }, # 
    {"href": "",
    "text": "N8N",
    "fondo": "blue" }, # 
    {"href": "",
    "text": "N8N",
    "fondo": "red" }, # 
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

