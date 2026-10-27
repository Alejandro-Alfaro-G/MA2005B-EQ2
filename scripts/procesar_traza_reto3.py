#!/usr/bin/env python3
from scapy.all import rdpcap, DNS
import sys

TYPE_MAP = {
    1: "A",
    2: "NS",
    6: "SOA",
    28: "AAAA",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    50: "NSEC3",
    51: "NSEC3PARAM"
}

def analizar_traza(pcap_file):
    try:
        paquetes = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error al abrir el archivo pcap: {e}")
        return

    print(f"{'='*95}")
    print(f"{'DOMINIO / RR':<30} | {'TIPO':<10} | {'TTL (s)':<8} | {'DETALLE / VALOR'}")
    print(f"{'='*95}")

    registros_vistos = set()

    for pkt in paquetes:
        if pkt.haslayer(DNS) and pkt[DNS].qr == 1:
            dns = pkt[DNS]
            for section, count in [(dns.an, dns.ancount), (dns.ns, dns.nscount)]:
                for i in range(count):
                    try:
                        rr = section[i]
                        nombre = rr.rrname.decode('utf-8') if isinstance(rr.rrname, bytes) else str(rr.rrname)
                        tipo_num = rr.type
                        tipo = TYPE_MAP.get(tipo_num, str(tipo_num))
                        ttl = rr.ttl

                        if tipo == "A":
                            valor = str(rr.rdata)
                        elif tipo == "NS":
                            valor = rr.rdata.decode('utf-8') if isinstance(rr.rdata, bytes) else str(rr.rdata)
                        elif tipo == "SOA":
                            mname = rr.mname.decode('utf-8') if isinstance(rr.mname, bytes) else str(rr.mname)
                            valor = f"MNAME: {mname}, Serial: {rr.serial}"
                        elif tipo == "DNSKEY":
                            valor = f"Flags: {rr.flags}, Alg: {rr.algorithm}"
                        elif tipo == "DS":
                            valor = f"KeyTag: {rr.keytag}, Alg: {rr.algorithm}, DigestType: {rr.digesttype}"
                        elif tipo == "RRSIG":
                            type_cov = TYPE_MAP.get(rr.typecovered, str(rr.typecovered))
                            signer = rr.signersname.decode('utf-8') if isinstance(rr.signersname, bytes) else str(rr.signersname)
                            valor = f"Covers: {type_cov}, Alg: {rr.algorithm}, KeyTag: {rr.keytag}, Signer: {signer}"
                        elif tipo in ("NSEC3", "NSEC3PARAM"):
                            valor = f"HashAlg: {getattr(rr, 'hashalg', 1)}, Iterations: {getattr(rr, 'iterations', 10)}"
                        else:
                            valor = str(getattr(rr, 'rdata', ''))[:40]

                        identificador = (nombre, tipo, valor)
                        if identificador not in registros_vistos:
                            registros_vistos.add(identificador)
                            print(f"{nombre:<30} | {tipo:<10} | {ttl:<8} | {valor}")
                    except Exception:
                        continue

    print(f"{'='*95}\n")

if __name__ == "__main__":
    archivo = sys.argv[1] if len(sys.argv) > 1 else "trazas_reto3.pcapng"
    analizar_traza(archivo)
