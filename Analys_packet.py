from scapy.all import sniff
from collections import defaultdict
import time
import re

activite_ip = defaultdict(list)

def packet_capture(packet):
    if packet.haslayer('IP'):
        src_ip = packet ['IP'].src
        dst_ip = packet ['IP'].dst
        if packet.haslayer('TCP'):
            src_port = packet ['TCP'].sport
            dst_port = packet ['TCP'].dport
            data = packet['Raw'].load if packet.haslayer('Raw') else None
            activite_ip[src_ip].append((dst_ip, src_port, dst_port, data))
        elif packet.haslayer('UPD'):
            src_port = packet['UPD'].sport
            dst_port = packet['UPD'].dport
            data = packet ['Raw'].load if packet.haslayer('Raw') else None 
            activite_ip[src_ip].append((dst_ip, src_port, dst_port, data))


def start_capture():
    print('Demarrage de la capture des paquets . . .')
    sniff(prn=packet_capture, store=0, filter='ip', count = 0)

def clean_data(data):
    try:
        decoded_data= data.decode('utf-8',errors = 'replace')
        cleaned_data = re.sub(r'[^\x20-\x7E]', '', decoded_data)
        return cleaned_data
    except Exception as e:
        return data.hex()


def affichage_activité():
    while True:
        time.sleep(10)
        print('\nActivité sur le Réseau :')
        for ip , activity in activite_ip.items():
            print(f'Adresse IP {ip} a communiquéé avec :')
            for dst_ip, src_port, dst_port, data in activity:
                print(f' --> {dst_ip} Le port de envoyeur {src_port}, Le port du receveur {dst_port}')
                if data:
                    cleaned_data = clean_data(data)
                    if cleaned_data == data.hex():
                        print(f' Données Envoyées (hex)---> {cleaned_data}')
                    else:
                        print(f' Données Envoyées ---> {cleaned_data}')
                else:
                    print(' aucune données brute. . .')

if __name__ == '__main__':
    import threading
    capture_thread = threading.Thread(target=start_capture)
    capture_thread.start()
    affichage_activité()