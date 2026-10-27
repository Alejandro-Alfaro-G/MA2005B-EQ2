#!/usr/bin/env python3
from scapy.all import rdpcap, DNS, DNSRR
import sys

# Mapeo de tipos de registros DNS
TYPE_MAP = {
    1: "A",
    2: "NS",
    6: "SOA",
    28: "AAAA"
}

def analizar_traza(pcap_file):
    try:
        paquetes = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error al abrir el archivo pcap: {e}")
        return

    print(f"{'='*80}")
    print(f"{'DOMINIO / RR':<35} | {'TIPO':<6} | {'TTL (s)':<8} | {'VALOR / DATOS'}")
    print(f"{'='*80}")

    registros_vistos = set()

    for pkt in paquetes:
        if pkt.haslayer(DNS) and pkt[DNS].qr == 1:  # Solo respuestas DNS (qr=1)
            dns = pkt[DNS]

            # Iterar sobre las respuestas (Answers)
            for i in range(dns.ancount):
                rr = dns.an[i]
                nombre = rr.rrname.decode('utf-8')
                tipo_num = rr.type
                tipo = TYPE_MAP.get(tipo_num, str(tipo_num))
                ttl = rr.ttl

                # Procesar el valor según el tipo de registro
                if tipo == "A":
                    rdata = rr.rdata
                elif tipo == "NS":
                    rdata = rr.rdata.decode('utf-8')
                elif tipo == "SOA":
                    mname = rr.mname.decode('utf-8')
                    rname = rr.rname.decode('utf-8')
                    serial = rr.serial
                    rdata = f"MNAME: {mname}, RNAME: {rname}, Serial: {serial}"
                else:
                    rdata = str(rr.rdata)

                identificador = (nombre, tipo, str(rdata))
                if identificador not in registros_vistos:
                    registros_vistos.add(identificador)
                    print(f"{nombre:<35} | {tipo:<6} | {ttl:<8} | {rdata}")

    print(f"{'='*80}\n")

if __name__ == "__main__":
    archivo = sys.argv[1] if len(sys.argv) > 1 else "dns_lab.pcapng"
    analizar_traza(archivo)
