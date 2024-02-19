from scapy.all import *

# Adresse IP source de l'utilisateur
src_ip = "127.0.0.3"

# Adresse IP de destination (serveur local)
dst_ip = "127.0.0.1"

# Port de destination (HTTP)
dst_port = 80

# Nombre de tentatives de connexion
num_attempts = 5

# Liste pour stocker les paquets de chaque tentative
packets = []

# Boucle pour créer et envoyer les paquets pour chaque tentative
for i in range(num_attempts):
    # Construire le paquet SYN
    syn_pkt = IP(src=src_ip, dst=dst_ip)/TCP(dport=dst_port, flags="S")

    # Envoyer le paquet SYN et recevoir la réponse SYN-ACK
    syn_ack_pkt = sr1(syn_pkt)

    # Extraire les numéros de séquence et d'acquittement du SYN-ACK
    seq_num = syn_ack_pkt[TCP].ack
    ack_num = syn_ack_pkt[TCP].seq + 1

    # Construire le paquet ACK pour compléter le 3-way handshake
    ack_pkt = IP(src=src_ip, dst=dst_ip)/TCP(dport=dst_port, flags="A", seq=seq_num, ack=ack_num)

    # Ajouter les paquets à la liste
    packets.extend([syn_pkt, syn_ack_pkt, ack_pkt])

# Enregistrer les paquets dans un fichier pcap
wrpcap("multiple_attempts.pcap", packets)
