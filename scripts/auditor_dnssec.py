#!/usr/bin/env python3
import sys
import time
import datetime
import dns.message
import dns.query
import dns.rdatatype
import dns.dnssec

RECURSIVE_SECURE = "172.30.0.101"
RECURSIVE_INSECURE = "172.30.0.100"
ROOT_SERVER = "172.30.0.10"

# Algoritmos autorizados según RFC 8624
ALGO_STATUS = {
    1: ("RSAMD5", "NO AUTORIZADO / OBSOLETO (RFC 8624)"),
    3: ("DSA", "NO AUTORIZADO (RFC 8624)"),
    5: ("RSASHA1", "NO AUTORIZADO / OBSOLETO (RFC 8624)"),
    7: ("RSASHA1-NSEC3-SHA1", "NO RECOMENDADO"),
    8: ("RSASHA256", "AUTORIZADO (Recomendado)"),
    10: ("RSASHA512", "AUTORIZADO"),
    13: ("ECDSAP256SHA256", "AUTORIZADO (Estándar recomendado)"),
    14: ("ECDSAP384SHA384", "AUTORIZADO"),
    15: ("ED25519", "AUTORIZADO")
}

def consultar(dominio, tipo, server):
    query = dns.message.make_query(dominio, tipo, want_dnssec=True)
    t0 = time.time()
    try:
        response = dns.query.udp(query, server, timeout=2)
        elapsed = (time.time() - t0) * 1000
        return response, elapsed
    except Exception as e:
        return None, 0

def auditar_dnskey(dominio, server):
    resp, _ = consultar(dominio, "DNSKEY", server)
    if not resp:
        return []
    hallazgos = []
    for rrset in resp.answer:
        if rrset.rdtype == dns.rdatatype.DNSKEY:
            for rdata in rrset:
                algo_num = rdata.algorithm
                algo_nombre, estado = ALGO_STATUS.get(algo_num, (f"Algoritmo {algo_num}", "DESCONOCIDO / NO ESTANDAR"))
                tipo_llave = "KSK (Key Signing Key)" if rdata.flags == 257 else "ZSK (Zone Signing Key)" if rdata.flags == 256 else f"Flags: {rdata.flags}"
                key_tag = dns.dnssec.key_id(rdata)
                hallazgos.append({
                    "key_tag": key_tag,
                    "flags": rdata.flags,
                    "tipo": tipo_llave,
                    "algoritmo": algo_nombre,
                    "estado_algoritmo": estado,
                    "protocol": rdata.protocol
                })
    return hallazgos

def auditar_rrsig(resp):
    firmas = []
    if not resp:
        return firmas
    now = time.time()
    for rrset in resp.answer + resp.authority:
        if rrset.rdtype == dns.rdatatype.RRSIG:
            for sig in rrset:
                inicio = datetime.datetime.fromtimestamp(sig.inception, tz=datetime.timezone.utc)
                expira = datetime.datetime.fromtimestamp(sig.expiration, tz=datetime.timezone.utc)
                valida = sig.inception <= now <= sig.expiration
                firmas.append({
                    "cubre_tipo": dns.rdatatype.to_text(sig.type_covered),
                    "signer": str(sig.signer),
                    "key_tag": sig.key_tag,
                    "inicio": inicio.strftime('%Y-%m-%d %H:%M:%S UTC'),
                    "expiracion": expira.strftime('%Y-%m-%d %H:%M:%S UTC'),
                    "estado": "VIGENTE" if valida else "CADUCADA / INVALIDA"
                })
    return firmas

def auditar_ds(hijo, padre, server_padre, server_hijo):
    resp_ds, _ = consultar(hijo, "DS", server_padre)
    ds_records = []
    if resp_ds:
        for rrset in resp_ds.answer + resp_ds.authority:
            if rrset.rdtype == dns.rdatatype.DS:
                for ds in rrset:
                    ds_records.append(ds)
    
    if not ds_records:
        return "SIN REGISTRO DS EN EL PADRE (Inseguro o No Delegado)"

    resp_keys, _ = consultar(hijo, "DNSKEY", server_hijo)
    ksks = []
    if resp_keys:
        for rrset in resp_keys.answer:
            if rrset.rdtype == dns.rdatatype.DNSKEY:
                for k in rrset:
                    if k.flags == 257:
                        ksks.append(k)

    for ds in ds_records:
        for ksk in ksks:
            ds_calculado = dns.dnssec.make_ds(hijo, ksk, 'SHA256')
            if ds.digest == ds_calculado.digest and ds.key_tag == ds_calculado.key_tag:
                return f"CADENA INTEGRA (KeyTag={ds.key_tag} coincide exactamente)"
    
    return f"CADENA ROTA (El DS publicado KeyTag={ds_records[0].key_tag} no coincide con la KSK real del hijo)"

def probar_zone_walking(dominio, server):
    nombres_descubiertos = []
    siguiente = f"aaa.{dominio}"
    es_nsec3 = False
    
    for _ in range(5):
        resp, _ = consultar(siguiente, "A", server)
        if not resp:
            break
        for rrset in resp.authority:
            if rrset.rdtype == dns.rdatatype.NSEC:
                for rdata in rrset:
                    actual = str(rrset.name)
                    proximo = str(rdata.next)
                    if proximo not in nombres_descubiertos:
                        nombres_descubiertos.append(proximo)
                    siguiente = proximo
            elif rrset.rdtype == dns.rdatatype.NSEC3:
                es_nsec3 = True
                break
        if es_nsec3 or not nombres_descubiertos:
            break
    
    if es_nsec3:
        return "PROTEGIDO: La zona usa NSEC3. No es posible realizar Zone Walking (hashes salados)."
    elif nombres_descubiertos:
        return f"VULNERABLE A ZONE WALKING (NSEC Plano): Nombres revelados -> {', '.join(nombres_descubiertos)}"
    else:
        return "Sin registros NSEC/NSEC3 detectados"

def main():
    print("=" * 75)
    print("   HERRAMIENTA DE AUDITORÍA Y VERIFICACIÓN DNSSEC - RETO ETAPA 4")
    print("=" * 75)
    
    dominios = [
        ("beta.signed.", "172.30.0.50", "signed.", "172.30.0.40"),
        ("delta.signed.", "172.30.0.50", "signed.", "172.30.0.40"),
        ("epsilon.signed.", "172.30.0.50", "signed.", "172.30.0.40"),
        ("gamma.signed.", "172.30.0.60", "signed.", "172.30.0.40"),
        ("expirado.test.", "172.30.0.80", "test.", "172.30.0.70"),
        ("ds-roto.test.", "172.30.0.80", "test.", "172.30.0.70"),
        ("alg-invalido.test.", "172.30.0.80", "test.", "172.30.0.70"),
    ]

    for dom, srv_hijo, padre, srv_padre in dominios:
        print(f"\n>>> AUDITANDO DOMINIO: {dom} (Autoritativo: {srv_hijo})")
        
        # 1. Auditoría DNSKEY
        keys = auditar_dnskey(dom, srv_hijo)
        print(f"  [1] Llaves DNSKEY detectadas: {len(keys)}")
        for k in keys:
            print(f"      - Tag: {k['key_tag']} | {k['tipo']} | Algoritmo: {k['algoritmo']} -> [{k['estado_algoritmo']}]")
            
        # 2. Auditoría RRSIG
        resp_a, latencia = consultar(f"www.{dom}", "A", srv_hijo)
        firmas = auditar_rrsig(resp_a)
        print(f"  [2] Registros RRSIG: {len(firmas)}")
        for f in firmas:
            print(f"      - Cubre: {f['cubre_tipo']} | KeyTag: {f['key_tag']} | Estado: {f['estado']} (Expira: {f['expiracion']})")
            
        # 3. Auditoría DS y Cadena de Confianza
        estado_ds = auditar_ds(dom, padre, srv_padre, srv_hijo)
        print(f"  [3] Integridad de Cadena (DS en {padre}): {estado_ds}")
        
        # 4. Auditoría NSEC / Zone Walking
        res_walk = probar_zone_walking(dom, srv_hijo)
        print(f"  [4] Prevención de Enumeración: {res_walk}")
        
        # 5. Comparación de Comportamiento de Resolutores y TTL
        resp_sec, t_sec = consultar(f"www.{dom}", "A", RECURSIVE_SECURE)
        resp_insec, t_insec = consultar(f"www.{dom}", "A", RECURSIVE_INSECURE)
        
        status_sec = dns.rcode.to_text(resp_sec.rcode()) if resp_sec else "TIMEOUT"
        ad_sec = "SI" if (resp_sec and (resp_sec.flags & dns.flags.AD)) else "NO"
        status_insec = dns.rcode.to_text(resp_insec.rcode()) if resp_insec else "TIMEOUT"
        
        ttl_val = resp_sec.answer[0].ttl if (resp_sec and resp_sec.answer) else (resp_insec.answer[0].ttl if (resp_insec and resp_insec.answer) else "N/A")
        
        print(f"  [5] Comportamiento en Resolutores:")
        print(f"      - Validador (172.30.0.101): RCODE={status_sec} | Flag AD={ad_sec} | Latencia={t_sec:.1f}ms")
        print(f"      - Inseguro   (172.30.0.100): RCODE={status_insec} | Latencia={t_insec:.1f}ms")
        print(f"      - TTL Reportado: {ttl_val} segundos")

if __name__ == "__main__":
    main()
