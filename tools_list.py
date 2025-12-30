import streamlit as st
# https://docs.streamlit.io/develop/quick-reference/cheat-sheet

st.set_page_config(layout="wide")

st.subheader("Roberto's- Cybersecurity (Python and Artificial Intelligence)")
st.write("80 Cyber Tools by Roberto")
st.balloons()
st.snow()
st.toast("Loading...")
#greenyellow,lime,orangered,yellowgreen,deeppink,    darkmagenta,blueviolet,red, blue
links = [
    {"href": "https://github.com/web-roberto/cybersecurity_python/blob/main/1_1_1_hacking_buscadores_parte1/ninjadorks.py",
    "text": "Roberto's Cybersecurity Tool -> Google Hacking -> Hacking search engines",
    "fondo": "#ff00ff" },
    # 1_1_1_hacking_buscadores_parte1
]

col1, col2 = st.columns([6, 1], gap="small", vertical_alignment="top", border=True, width="stretch")

with col1:
    # st.success("Roberto's Cybersecurity Tool -> Google Hacking -> Hacking search engines") # 1_1_1_hacking_buscadores_parte1
    for link in links:
      st.markdown(f"""<a href="{link['href']}" target="_blank">
            <button style="background-color:#ff00ff;color:white;padding:0.5em 1em;margin:0.5em;width:100%;border:none;text-align:start;border-radius:8px;cursor:pointer;">
                {link['text']}
            </button></a>""",unsafe_allow_html=True)
    st.info("Roberto's Cybersecurity Tool -> Google Hacking -> Execution of Python Scripts")  # 1_1_3_ejecucion_scripts_python -> 40
    st.error("Roberto's Cybersecurity Tool -> Google Hacking -> Command Line Arguments")  # 1_1_4_argumentos_linea_comandos -> 41
    st.warning("Roberto's Cybersecurity Tool -> Google Hacking -> Generation of Results")  # 1_1_5_generacion_resultados -> 42
    st.success("Roberto's Cybersecurity Tool -> Google Hacking -> File Handling")  # 1_1_6_manejo_ficheros -> 43
    st.info("Roberto's Cybersecurity Tool -> Google Hacking -> Dorks with AI GPT4ALL")  # 1_1_7_dorks_ia_GPT4All -> 47
    st.error("Roberto's Cybersecurity Tool -> Google Hacking with AI -> Dorks with AI from OpenAI GPT4 ")  # 1_1_8_dorks_ia_OpenAI_GPT4_Parte1 -> 47
    st.warning("Roberto's Cybersecurity Tool  -> Google Hacking with AI -> Dorks with AI from OpenAI GPT4 -part 2")  # 1_1_9_dorks_ia_OpenAI_GPT4_Parte2 ->48
    st.success("Roberto's Cybersecurity Tool -> Information filtering with RegEx")  # 1_2_1_filtrado_informacion_regex -> smartsearch.pyv- video 49
    st.info("Roberto's Cybersecurity Tool  -> Information filtering with AI")  # 1_2_2_filtrado_informacion_IA->52
    st.error("Roberto's Cybersecurity Tool -> NinjaDork and Selenium Automation")  # 1_3_automatizacion_selenium -> 52
    st.warning("Roberto's Cybersecurity Tool -> Hacking with Search Engines and Selenium")  # 1_4_hacking_buscadores_selenium -> 54
    
    st.success("Roberto's Cybersecurity Tool -> Shodan with Python - Authentication and Login Automation")  #  2_1_1_shodan_python ->59
    st.info("Roberto's Cybersecurity Tool -> Authentication and Login Automation")  # 2_1_2_auth_login_automatizado -> 60 (código en doc y en github)
    st.error("Roberto's Cybersecurity Tool -> Selenium: Authentication and Login Automation ")  # 2_1_3_auth_login_selenium -> 61
    st.warning("Roberto's Cybersecurity Tool -> Multithreading with Python ")  # 2_1_4_multithreading_python -> 63
    st.success("Roberto's Cybersecurity Tool -> Waybackmachine")  # 2_2_waybackmachine
    st.info("Roberto's Cybersecurity Tool -> Dns Enumeration")  # 2_3_dns_enumeration
    st.error("Roberto's Cybersecurity Tool -> Whois Enumeration")  # 2_4_whois_enumeration
    st.warning("Roberto's Cybersecurity Tool -> Ip Geolocation")  # 2_5_ip_geolocation
    st.info("Roberto's Cybersecurity Tool -> Phone Geolocation")  # 2_6_phone_geolocation
    st.error("Roberto's Cybersecurity Tool -> Metadata Analyzer")  # 2_7_metadata_analyzer
    
    st.success("Roberto's Cybersecurity Tool -> Sniffer Tshark")  # 3_1_sniffer_tshark
    st.warning("Roberto's Cybersecurity Tool -> Sniffer Scapy")  # 3_2_sniffer_scapy
    st.info("Roberto's Cybersecurity Tool ->  Sockets")  # 3_3_sockets
    st.error("Roberto's Cybersecurity Tool -> Scan of Hosts Sockets")  # 3_4_1_escaneo_hosts_sockets
    st.warning("Roberto's Cybersecurity Tool -> Scan of Hosts Scapy")  # 3_4_2_escaneo_hosts_scapy
    st.success("Roberto's Cybersecurity Tool -> Scan ARP")  # 3_4_3_escaneo_arp
    st.info("Roberto's Cybersecurity Tool ->  Scan of ports")  # 3_4_4_escaneo_puerto
    st.error("Roberto's Cybersecurity Tool ->  Scan of Services")  #  3_4_5_escaneo_servicios
    st.success("Roberto's Cybersecurity Tool -> Discovery of Resources Network")  # 3_4_6_descubrimiento_recursos_red
    st.error("Roberto's Cybersecurity Tool ->  Scanner NMAP with Python")  #  3_5_nmap_scanner_python, que seria 3_4_5
    st.success("Roberto's Cybersecurity Tool -> AI Prioritization Scanning")  # 3_6_escaneo_priorizacion_IA, que seria 3_4_6

    st.warning("Roberto's Cybersecurity Tool -> Beautiful Soup")  # 4_1_beautiful_soup
    st.info("Roberto's Cybersecurity Tool -> Scanner of CVE Vulnerabilities")  # 4_2_1_escaner_vulnerabilidades_CVEs
    st.error("Roberto's Cybersecurity Tool -> Scanner of CVSS Vulnerabilities")  # 4_2_2_escaner_vulnerabilidades_CVSS
    st.success("Roberto's Cybersecurity Tool -> Scanner Vulnerabilities: results")  # 4_2_3_escaner_vulnerabilidades_resultados
    st.warning("Roberto's Cybersecurity Tool -> Nessus: session creation")  # 4_3_1_escaner_Nessus_creacion_sesion
    st.info("Roberto's Cybersecurity Tool -> Nessus: scannner creation")  # 4_3_2_escaner_Nessus_creacion_escaneo
    st.error("Roberto's Cybersecurity Tool -> Nessus: Scan results")  # 4_3_3_escaner_Nessus_resultado

    st.success("Roberto's Cybersecurity Tool -> Exploit Proftpd") # 5_1_exploit_proftpd
    st.warning("Roberto's Cybersecurity Tool -> Exploit Unrealircd")  # 5_2_exploit_unrealircd
    st.info("Roberto's Cybersecurity Tool -> Tcp Reverse Shell")   # 5_3_tcp_reverse_shell
    st.error("Roberto's Cybersecurity Tool -> Http Reverse Shell")  #  5_4_1_http_reverse_shell
    st.success("Roberto's Cybersecurity Tool -> One Liner AI")  # 5_4_2_one_liner_IA
    st.warning("Roberto's Cybersecurity Tool -> Https Reverse Shell")  # 5_5_https_reverse_shell
    st.info("Roberto's Cybersecurity Tool -> Metasploit Exploit modules")  # 5_6_1_pymetasploit_modulos_exploits
    st.error("Roberto's Cybersecurity Tool -> Pymetasploit Execution Exploits")  # 5_6_2_pymetasploit_ejecucion_exploits
    st.success("Roberto's Cybersecurity Tool -> Pymetasploit Sessions Handling")  # 5_6_3_pymetasploit_manejo_sesiones
    st.warning("Roberto's Cybersecurity Tool -> Keylogger")  # 5_7_keylogger

    st.info("Roberto's Cybersecurity Tool -> ARP Spoofing")  # 6_1_arp_spoofing
    st.error("Roberto's Cybersecurity Tool -> Netfilterqueue Interceptation")  # 6_2_1_netfilterqueue_interceptacion
    st.success("Roberto's Cybersecurity Tool ->  Netfilterqueue Modification")  # 6_2_2_netfilterqueue_modificacion
    st.warning("Roberto's Cybersecurity Tool -> Http Interceptor")  # 6_3_http_interceptor
    st.info("Roberto's Cybersecurity Tool -> DNS Spooging")  # 6_4_dns_spoofing
    st.error("Roberto's Cybersecurity Tool -> ARP Spooging Detector")  # 6_5_arp_spoofing_detector
    st.success("Roberto's Cybersecurity Tool -> SSH BRUTE FORCE")  # 6_6_ssh_brute_force
    st.warning("Roberto's Cybersecurity Tool -> DHCP Listener")  # 6_7_dhcp_listener
    st.info("Roberto's Cybersecurity Tool -> MAC Spoofing")  # 6_8_mac_spoofing
  
    st.error("Roberto's Cybersecurity Tool -> Spidering")  # 7_1_spidering
    st.success("Roberto's Cybersecurity Tool -> ZAP Analyzer.")  # 7_2_1_zap_analyzer
    st.warning("Roberto's Cybersecurity Tool -> ZAP Passive Analysis")  # 7_2_2_zap_analisis_pasivo
    st.error("Roberto's Cybersecurity Tool -> ZAP Active Analysis")  # 7_2_3_zap_analisis_activo
    st.info("Roberto's Cybersecurity Tool -> Autenticacion Python") # 7_3_autenticacion_python
    st.error("Roberto's Cybersecurity Tool -> XSS Scanner")  # 7_4_xss_scanner
    st.success("Roberto's Cybersecurity Tool -> SQLi Scanner")  # 7_5_sqli_scanner
    st.warning("Roberto's Cybersecurity Tool -> Subdomain Scanner")   # 7_6_subdomain_scanner
    st.info("Roberto's Cybersecurity Tool -> Web Content Discorery") # 7_7_web_content_discovery
    st.error("Roberto's Cybersecurity Tool -> Brute Force Web")  # 7_8_brute_force_web
    st.success("Roberto's Cybersecurity Tool -> BURP Suite Python")  # 7_9_burp_suite_python

    st.warning("Roberto's Cybersecurity Tool -> Cracking Passwords")  # 8_1_cracking_passwords
    st.info("Roberto's Cybersecurity Tool -> Cracking ZIP")  # 8_2_cracking_zip
    st.error("Roberto's Cybersecurity Tool -> Chrome Password Decrypto")  # 8_3_chrome_password_decryptor
    st.success("Roberto's Cybersecurity Tool -> WIFI Password Collector")  # 8_4_wifi_password_collector
    st.warning("Roberto's Cybersecurity Tool -> Windows Service")  # 8_5_1_windows_service
    st.info("Roberto's Cybersecurity Tool -> Windows Service ..nore")  # 8_5_2_windows_service
    st.error("Roberto's Cybersecurity Tool -> Evasion Defenses")  # 8_6_evasion_defensas
    st.success("Roberto's Cybersecurity Tool -> Exfiltration Steganography")  # 8_7_exfiltracion_esteganografia
with col2:
    #st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/blob/main/1_1_1_hacking_buscadores_parte1/ninjadorks.py")
    #st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/1_1_3_ejecucion_scripts_python")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/1_1_4_argumentos_linea_comandos")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/1_1_5_generacion_resultados")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/1_1_6_manejo_ficheros")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/1_1_7_dorks_ia_GPT4All")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/1_1_8_dorks_ia_OpenAI_GPT4_Parte1")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/1_1_9_dorks_ia_OpenAI_GPT4_Parte2")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/1_2_1_filtrado_informacion_regex")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/1_2_2_filtrado_informacion_IA")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/1_3_automatizacion_selenium")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/1_4_hacking_buscadores_selenium")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/2_1_1_shodan_python")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/2_1_2_auth_login_automatizado")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/2_1_3_auth_login_selenium")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/2_1_4_multithreading_python")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/2_2_waybackmachine")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/2_3_dns_enumeration")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/2_4_whois_enumeration")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/2_5_ip_geolocation")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/2_6_phone_geolocation")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/2_7_metadata_analyzer")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/3_1_sniffer_tshark")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/3_2_sniffer_scapy")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/3_3_sockets")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/3_4_1_escaneo_hosts_sockets")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/3_4_2_escaneo_hosts_scapy")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/3_4_3_escaneo_arp")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/3_4_4_escaneo_puertos")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/3_4_5_escaneo_servicios")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/3_4_6_descubrimiento_recursos_red")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/3_5_nmap_scanner_python")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/3_6_escaneo_priorizacion_IA")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/4_1_beautiful_soup")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/4_2_1_escaner_vulnerabilidades_CVEs")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/4_2_2_escaner_vulnerabilidades_CVSS")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/4_2_3_escaner_vulnerabilidades_resultados")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/4_3_1_escaner_Nessus_creacion_sesion")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/4_3_2_escaner_Nessus_creacion_escaneo")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/4_3_3_escaner_Nessus_resultados")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/5_1_exploit_proftpd")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/5_2_exploit_unrealircd")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/5_3_tcp_reverse_shell")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/5_4_1_http_reverse_shell")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/5_4_2_one_liner_IA")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/5_5_https_reverse_shell")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/5_6_1_pymetasploit_modulos_exploits")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/5_6_2_pymetasploit_ejecucion_exploits")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/5_6_3_pymetasploit_manejo_sesiones")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/5_7_keylogger")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/6_1_arp_spoofing")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/6_2_1_netfilterqueue_interceptacion")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/6_2_2_netfilterqueue_modificacion")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/6_3_http_interceptor")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/6_4_dns_spoofing")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/6_5_arp_spoofing_detector")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/6_6_ssh_brute_force")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/6_7_dhcp_listener")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/6_8_mac_spoofing")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/7_1_spidering")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/7_2_1_zap_analyzer")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/7_2_2_zap_analisis_pasivo")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/7_2_3_zap_analisis_activo")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/7_3_autenticacion_python")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/7_4_xss_scanner")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/7_5_sqli_scanner")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/7_6_subdomain_scanner")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/7_7_web_content_discovery")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/7_8_brute_force_web")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/7_9_burp_suite_python")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/8_1_cracking_passwords")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/8_2_cracking_zip")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/8_3_chrome_password_decryptor")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/8_4_wifi_password_collector")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/8_5_1_windows_service")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/8_5_2_windows_service")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/8_6_evasion_defensas")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/8_7_exfiltracion_esteganografia")
    st.write('')
   
