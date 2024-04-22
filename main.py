from scapy.all import sniff, TCP, UDP, ICMP, ARP

def process_packet(packet):
    print("Pacote Capturado:")
    print("-" * 50)

    if packet.haslayer("Ethernet"):
        src_mac = packet["Ethernet"].src
        dst_mac = packet["Ethernet"].dst
        print(f"Endereço MAC Origem: {src_mac}, Endereço MAC Destino: {dst_mac}")

    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        print(f"IP Origem: {src_ip}, IP Destino: {dst_ip}")

    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print(f"Porta Origem TCP: {src_port}, Porta Destino TCP: {dst_port}")

    if packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        print(f"Porta Origem UDP: {src_port}, Porta Destino UDP: {dst_port}")

    if packet.haslayer(ICMP):
        icmp_type = packet[ICMP].type
        icmp_code = packet[ICMP].code
        print(f"Tipo ICMP: {icmp_type}, Código ICMP: {icmp_code}")

    # Verifica se o pacote tem camada ARP e exibe endereços IP e MAC
    if packet.haslayer(ARP):
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc
        dst_ip = packet[ARP].pdst
        dst_mac = packet[ARP].hwdst
        print(f"ARP - IP Origem: {src_ip}, MAC Origem: {src_mac}, IP Destino: {dst_ip}, MAC Destino: {dst_mac}")

    print("-" * 50)

# Mensagem inicial
print("Iniciando rastreamento... Ready to Hack!")

# Captura e processa pacotes indefinidamente
try:
    sniff(prn=process_packet, store=0)
except KeyboardInterrupt:
    print("\nCaptura de pacotes interrompida. Hora de desaparecer.")
