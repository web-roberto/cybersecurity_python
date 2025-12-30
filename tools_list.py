import streamlit as st
# https://docs.streamlit.io/develop/quick-reference/cheat-sheet

st.set_page_config(layout="wide")

st.subheader("Roberto's- Cybersecurity (Python and Artificial Intelligence)")
st.write("80 Cyber Tools by Roberto")
st.balloons()
st.snow()
st.toast("Loading...")

col1, col2 = st.columns([6, 1], gap="small", vertical_alignment="top", border=True, width="stretch")

with col1:
    st.success("Roberto's Cyber Tool -> Google Hacking -> Hacking search engines") # 1_1_1_hacking_buscadores_parte1
    st.success("Roberto's Cyber Tool -> Google Hacking -> Execution of Python Scripts")  # 1_1_3_ejecucion_scripts_python -> 40
    st.success("Roberto's Cyber Tool -> Google Hacking -> Command Line Arguments")  # 1_1_4_argumentos_linea_comandos -> 41
    st.success("Roberto's Cyber Tool -> Google Hacking -> Generation of Results")  # 1_1_5_generacion_resultados -> 42
    st.success("Roberto's Cyber Tool -> Google Hacking -> File Handling")  # 1_1_6_manejo_ficheros -> 43
    st.success("Roberto's Cyber Tool -> Google Hacking -> Dorks with AI GPT4ALL.")  # 1_1_7_dorks_ia_GPT4All -> 47
    st.success("Roberto's Cyber Tool -> Google Hacking with AI -> Dorks with AI from OpenAI GPT4 ")  # 1_1_8_dorks_ia_OpenAI_GPT4_Parte1 -> 47
    st.success("Roberto's Cyber Tool  -> Google Hacking with AI -> Dorks with AI from OpenAI GPT4 -part 2")  # 1_1_9_dorks_ia_OpenAI_GPT4_Parte2 ->48
    st.success("Roberto's Cyber Tool -> Information filtering with RegEx")  # 1_2_1_filtrado_informacion_regex -> smartsearch.pyv- video 49
    st.success("Roberto's Cyber Tool  -> Information filtering with AI")  # 1_2_2_filtrado_informacion_IA->52
    st.success("Roberto's Cyber Tool -> NinjaDork and Selenium Automation")  # 1_3_automatizacion_selenium -> 52
    st.success("Roberto's Cyber Tool -> Hacking with Search Engines and Selenium")  # 1_4_hacking_buscadores_selenium -> 54
    
    st.success("Roberto's Cyber Tool -> Shodan with Python - Authentication and Login Automation")  #  2_1_1_shodan_python ->59
    st.success("Roberto's Cyber Tool -> Authentication and Login Automation ")  # 2_1_2_auth_login_automatizado -> 60 (código en doc y en github)
    st.success("Roberto's Cyber Tool -> Selenium: Authentication and Login Automation ")  # 2_1_3_auth_login_selenium -> 61
    st.success("Roberto's Cyber Tool -> ........ ")  # 2_1_4_multithreading_python -> 63
    st.success("Roberto's Cyber Tool ->  ........")  # 2_2_waybackmachine
    st.success("Roberto's Cyber Tool ->  ........")  # 2_3_dns_enumeration
    st.success("Roberto's Cyber Tool ->  ........")  # 2_4_whois_enumeration
    st.success("Roberto's Cyber Tool ->  ........")  # 2_5_ip_geolocation
    st.info("Roberto's Cyber Tool ->  ........")  # 2_6_phone_geolocation
    st.error("Roberto's Cyber Tool ->  ........")  # 2_7_metadata_analyzer
    
    st.success("CYBERSECURITY TOOL -> ........")  # 3_1_sniffer_tshark
    st.warning("CYBERSECURITY TOOL -> ........")  # 3_2_sniffer_scapy
    st.info("CYBERSECURITY TOOL ->  ........")  # 3_3_sockets
    st.error("CYBERSECURITY TOOL ->  ........")  # 3_4_1_escaneo_hosts_sockets
    st.success("CYBERSECURITY TOOL ->  ........")  # 3_4_2_escaneo_hosts_scapy
    st.warning("CYBERSECURITY TOOL ->  ........")  # 3_4_3_escaneo_arp
    st.info("CYBERSECURITY TOOL ->  ........")  # 3_4_4_escaneo_puerto
    st.error("CYBERSECURITY TOOL ->  ........")  #  3_4_5_escaneo_servicios
    st.success("CYBERSECURITY TOOL ->  ........")  # 3_4_6_descubrimiento_recursos_red
    st.error("CYBERSECURITY TOOL ->  ........")  #  3_5_nmap_scanner_python, que seria 3_4_5
    st.success("CYBERSECURITY TOOL ->  ........")  # 3_6_escaneo_priorizacion_IA, que seria 3_4_6

    st.warning("CYBERSECURITY TOOL ->  ........")  # 4_1_beautiful_soup
    st.info("CYBERSECURITY TOOL ->  ........")  # 4_2_1_escaner_vulnerabilidades_CVEs
    st.error("CYBERSECURITY TOOL ->  ........")  # 4_2_2_escaner_vulnerabilidades_CVSS
    st.success("CYBERSECURITY TOOL ->  ........")  # 4_2_3_escaner_vulnerabilidades_resultados
    st.warning("CYBERSECURITY TOOL ->  ........")  # 4_3_1_escaner_Nessus_creacion_sesion
    st.info("CYBERSECURITY TOOL ->  ........")  # 4_3_2_escaner_Nessus_creacion_escaneo
    st.error("CYBERSECURITY TOOL ->  ........")  # 4_3_3_escaner_Nessus_resultado

    st.success("CYBERSECURITY TOOL ->  ........") # 5_1_exploit_proftpd
    st.warning("CYBERSECURITY TOOL ->  ........")  # 5_2_exploit_unrealircd
    st.info("CYBERSECURITY TOOL -> ........")   # 5_3_tcp_reverse_shell
    st.error("CYBERSECURITY TOOL ->  ........")  #  5_4_1_http_reverse_shell
    st.success("CYBERSECURITY TOOL ->  ........")  # 5_4_2_one_liner_IA
    st.warning("CYBERSECURITY TOOL ->  ........")  # 5_5_https_reverse_shell
    st.info("CYBERSECURITY TOOL ->  ........")  # 5_6_1_pymetasploit_modulos_exploits
    st.error("CYBERSECURITY TOOL ->  ........")  # 5_6_2_pymetasploit_ejecucion_exploits
    st.success("CYBERSECURITY TOOL ->  ........")  # 5_6_3_pymetasploit_manejo_sesiones
    st.warning("CYBERSECURITY TOOL ->  ........")  # 5_7_keylogger

    st.info("CYBERSECURITY TOOL ->6_1_ ...")  # 6_1_arp_spoofing
    st.error("CYBERSECURITY TOOL -> 6_2_1_...")  # 6_2_1_netfilterqueue_interceptacion
    st.success("CYBERSECURITY TOOL -> 6_2_2_...")  # 6_2_2_netfilterqueue_modificacion
    st.warning("CYBERSECURITY TOOL -> 6_3...")  # 6_3_http_interceptor
    st.info("CYBERSECURITY TOOL -> 6_4...")  # 6_4_dns_spoofing
    st.error("CYBERSECURITY TOOL -> 6_5...")  # 6_5_arp_spoofing_detector
    st.success("CYBERSECURITY TOOL -> 6_6...")  # 6_6_ssh_brute_force
    st.warning("CYBERSECURITY TOOL -> 6_7...")  # 6_7_dhcp_listener
    st.info("CYBERSECURITY TOOL -> 6_8...")  # 6_8_mac_spoofing
  
    st.error("CYBERSECURITY TOOL -> 7_1_...")  # 7_1_spidering
    st.success("CYBERSECURITY TOOL -> 7_2_1_...")  # 7_2_1_zap_analyzer
    st.warning("CYBERSECURITY TOOL -> 7_2_2...")  # 7_2_2_zap_analisis_pasivo
    st.warning("CYBERSECURITY TOOL -> 7_2_3...")  # 7_2_3_zap_analisis_activo
    st.info("CYBERSECURITY TOOL -> 7_3...") # 7_3_autenticacion_python
    st.error("CYBERSECURITY TOOL ->7_4...")  # 7_4_xss_scanner
    st.success("CYBERSECURITY TOOL -> 7_5...")  # 7_5_sqli_scanner
    st.warning("CYBERSECURITY TOOL -> 7_6...")   # 7_6_subdomain_scanner
    st.info("CYBERSECURITY TOOL -> 7_7...") # 7_7_web_content_discovery
    st.error("CYBERSECURITY TOOL ->7_8 ...")  # 7_8_brute_force_web
    st.success("CYBERSECURITY TOOL -> 7_9...")  # 7_9_burp_suite_python

    st.warning("CYBERSECURITY TOOL -> 8_1...")  # 8_1_cracking_passwords
    st.info("CYBERSECURITY TOOL -> 8_2...")  # 8_2_cracking_zip
    st.error("CYBERSECURITY TOOL -> 8_3...")  # 8_3_chrome_password_decryptor
    st.success("CYBERSECURITY TOOL -> 8_4...")  # 8_4_wifi_password_collector
    st.warning("CYBERSECURITY TOOL -> 8_5_1...")  # 8_5_1_windows_service
    st.info("CYBERSECURITY TOOL -> 8_5_2...")  # 8_5_2_windows_service
    st.error("CYBERSECURITY TOOL -> 8_6...")  # 8_6_evasion_defensas
    st.success("CYBERSECURITY TOOL -> 8_7...")  # 8_7_exfiltracion_esteganografia
   
with col2:
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/blob/main/1_1_1_hacking_buscadores_parte1/ninjadorks.py")
    st.write('')
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
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/2_1_3_auth_login_selenium")
    st.write('-por aqui-2_1_3_a')
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
    st.write('3_2_sniffer_s')
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
    st.write('5_1_exploit_proftpd')
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
    st.write('6_5_arp_spoofing_detector')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/6_6_ssh_brute_force")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/6_7_dhcp_listener")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/6_8_mac_spoofing")
    st.write('')
    st.link_button("Code Github", "https://github.com/web-roberto/cybersecurity_python/tree/main/7_1_spidering")
    st.write('7_1_spidering')
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
    st.write('8_1_cracking_passwords')
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
    st.write('8_7_exfiltracion_esteganografi')
   
