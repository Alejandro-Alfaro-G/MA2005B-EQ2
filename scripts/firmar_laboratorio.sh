#!/bin/bash
set -e

echo "=========================================================================="
echo "   AUTOMATIZACIÓN DE FIRMADO Y CADENA DE CONFIANZA DNSSEC (RETO FINAL)   "
echo "=========================================================================="

cd "$(dirname "$0")"

# 0. Limpiar artefactos criptográficos previos
echo "[+] Limpiando llaves, firmas y dssets anteriores..."
rm -f */zones/K* */zones/dsset-* */zones/*.signed */zones/*.signed.signed

# -------------------------------------------------------------------------
# FASE 1: HIJOS DE SIGNED (beta, delta, epsilon)
# -------------------------------------------------------------------------
echo "[+] Firmando zonas hijas bajo signed. (dns-beta)..."

# 1.1 beta.signed (ECDSA P-256 + NSEC3)
docker exec -w /var/lib/bind dns-beta dnssec-keygen -a ECDSAP256SHA256 beta.signed
docker exec -w /var/lib/bind dns-beta dnssec-keygen -f KSK -a ECDSAP256SHA256 beta.signed
cat beta/zones/Kbeta.signed.*.key >> beta/zones/db.beta.signed
docker exec -w /var/lib/bind dns-beta dnssec-signzone -3 A1B2C3D4 -N INCREMENT -o beta.signed -t db.beta.signed

# 1.2 delta.signed (ECDSA P-256 + NSEC plano para demostración de Zone Walking)
docker exec -w /var/lib/bind dns-beta dnssec-keygen -a ECDSAP256SHA256 delta.signed
docker exec -w /var/lib/bind dns-beta dnssec-keygen -f KSK -a ECDSAP256SHA256 delta.signed
cat beta/zones/Kdelta.signed.*.key >> beta/zones/db.delta.signed
docker exec -w /var/lib/bind dns-beta dnssec-signzone -N INCREMENT -o delta.signed -t db.delta.signed

# 1.3 epsilon.signed (RSA/SHA-256 de 2048 bits + NSEC3)
docker exec -w /var/lib/bind dns-beta dnssec-keygen -a RSASHA256 -b 2048 epsilon.signed
docker exec -w /var/lib/bind dns-beta dnssec-keygen -f KSK -a RSASHA256 -b 2048 epsilon.signed
cat beta/zones/Kepsilon.signed.*.key >> beta/zones/db.epsilon.signed
docker exec -w /var/lib/bind dns-beta dnssec-signzone -3 E1F2A3B4 -N INCREMENT -o epsilon.signed -t db.epsilon.signed

docker restart dns-beta dns-gamma

# -------------------------------------------------------------------------
# FASE 2: HIJOS DE TEST (expirado, ds-roto, alg-invalido)
# -------------------------------------------------------------------------
echo "[+] Firmando zonas hijas con fallos controlados bajo test. (dns-test-hijos)..."

# 2.1 expirado.test (Firmas forzadas en 2025 mediante banderas -P, -s y -e)
docker exec -w /var/lib/bind dns-test-hijos dnssec-keygen -a ECDSAP256SHA256 -P 20241201000000 -A 20241201000000 expirado.test
docker exec -w /var/lib/bind dns-test-hijos dnssec-keygen -f KSK -a ECDSAP256SHA256 -P 20241201000000 -A 20241201000000 expirado.test
cat test-hijos/zones/Kexpirado.test.*.key >> test-hijos/zones/db.expirado.test
docker exec -w /var/lib/bind dns-test-hijos dnssec-signzone -P -s 20250101000000 -e 20250201000000 -N INCREMENT -o expirado.test -t db.expirado.test

# 2.2 ds-roto.test (Zona firmada válidamente; el DS roto se inyectará en el padre)
docker exec -w /var/lib/bind dns-test-hijos dnssec-keygen -a ECDSAP256SHA256 ds-roto.test
docker exec -w /var/lib/bind dns-test-hijos dnssec-keygen -f KSK -a ECDSAP256SHA256 ds-roto.test
cat test-hijos/zones/Kds-roto.test.*.key >> test-hijos/zones/db.ds-roto.test
docker exec -w /var/lib/bind dns-test-hijos dnssec-signzone -3 A1B2C3D4 -N INCREMENT -o ds-roto.test -t db.ds-roto.test

# 2.3 alg-invalido.test (Zona firmada únicamente con RSASHA1 - Algoritmo 5, RFC 8624)
docker exec -w /var/lib/bind dns-test-hijos dnssec-keygen -a RSASHA1 -b 1024 alg-invalido.test
docker exec -w /var/lib/bind dns-test-hijos dnssec-keygen -f KSK -a RSASHA1 -b 1024 alg-invalido.test
cat test-hijos/zones/Kalg-invalido.test.*.key >> test-hijos/zones/db.alg-invalido.test
docker exec -w /var/lib/bind dns-test-hijos dnssec-signzone -N INCREMENT -o alg-invalido.test -t db.alg-invalido.test

docker restart dns-test-hijos

# -------------------------------------------------------------------------
# FASE 3: TLDs (signed. y test.)
# -------------------------------------------------------------------------
echo "[+] Inyectando registros DS y firmando TLDs..."

# 3.1 TLD signed.
sed -i '/IN DS/d' signed/zones/db.signed
cat beta/zones/dsset-beta.signed. beta/zones/dsset-delta.signed. beta/zones/dsset-epsilon.signed. >> signed/zones/db.signed
docker exec -w /var/lib/bind dns-signed dnssec-keygen -a ECDSAP256SHA256 signed
docker exec -w /var/lib/bind dns-signed dnssec-keygen -f KSK -a ECDSAP256SHA256 signed
cat signed/zones/Ksigned.*.key >> signed/zones/db.signed
docker exec -w /var/lib/bind dns-signed dnssec-signzone -3 B1C2D3E4 -N INCREMENT -o signed -t db.signed
docker restart dns-signed

# 3.2 TLD test. (Inyecta DS legítimos de expirado y alg-invalido, y DS alterado con KeyTag 65000 para ds-roto)
sed -i '/IN DS/d' test/zones/db.test
echo "ds-roto.test. IN DS 65000 13 2 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF" >> test/zones/db.test
cat test-hijos/zones/dsset-expirado.test. test-hijos/zones/dsset-alg-invalido.test. >> test/zones/db.test
docker exec -w /var/lib/bind dns-test dnssec-keygen -a ECDSAP256SHA256 test
docker exec -w /var/lib/bind dns-test dnssec-keygen -f KSK -a ECDSAP256SHA256 test
cat test/zones/Ktest.*.key >> test/zones/db.test
docker exec -w /var/lib/bind dns-test dnssec-signzone -3 C1D2E3F4 -N INCREMENT -o test -t db.test
docker restart dns-test

# -------------------------------------------------------------------------
# FASE 4: ZONA RAÍZ (.) Y ACTUALIZACIÓN DEL TRUST ANCHOR
# -------------------------------------------------------------------------
echo "[+] Inyectando DS de signed. y test. a la raíz y firmando..."

sed -i '/IN DS/d' root/zones/db.root
cat signed/zones/dsset-signed. test/zones/dsset-test. >> root/zones/db.root
docker exec -w /var/lib/bind dns-root dnssec-keygen -a ECDSAP256SHA256 .
docker exec -w /var/lib/bind dns-root dnssec-keygen -f KSK -a ECDSAP256SHA256 .
cat root/zones/K.*.key >> root/zones/db.root
docker exec -w /var/lib/bind dns-root dnssec-signzone -3 C1D2E3F4 -N INCREMENT -o . -t db.root
docker restart dns-root

# 4.1 Extraer la KSK pública de la raíz e inyectarla como Trust Anchor en dns-recursive2
ROOT_KSK_KEY=$(grep "IN DNSKEY 257 3 13" root/zones/K.*.key | awk '{print $7, $8}')
cat << TA_EOF > recursive2/named.conf
options {
    directory "/var/cache/bind";
    listen-on { 172.30.0.101; };
    listen-on-v6 { none; };
    recursion yes;
    allow-query { any; };
    dnssec-validation yes;
};

zone "." {
    type hint;
    file "/usr/share/dns/root.hints";
};

trust-anchors {
    . static-key 257 3 13 "${ROOT_KSK_KEY}";
};
TA_EOF

docker restart dns-recursive1 dns-recursive2
docker exec dns-recursive1 rndc flush
docker exec dns-recursive2 rndc flush

echo "=========================================================================="
echo "   ¡ÁRBOL DNSSEC COMPLETAMENTE FIRMADO, VINCULADO Y SINCRONIZADO!       "
echo "=========================================================================="
