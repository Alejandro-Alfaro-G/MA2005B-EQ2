#!/bin/bash
clear
echo "=========================================================================================="
echo "          EVALUACION EXPERIMENTAL DNSSEC - PRESENTACION EJECUTIVA (RETO FINAL)"
echo "=========================================================================================="
printf "%-26s | %-12s | %-8s | %-12s | %-8s | %s\n" "DOMINIO CONSULTADO" "RCODE (VAL)" "FLAG AD" "RCODE (INSEC)" "FLAG AD" "IP / RESULTADO"
echo "------------------------------------------------------------------------------------------"

DOMINIOS=(
  "www.alpha.unsigned."
  "www.delta.unsigned."
  "www.epsilon.unsigned."
  "www.zeta.unsigned."
  "www.beta.signed."
  "www.delta.signed."
  "www.epsilon.signed."
  "www.gamma.signed."
  "www.zeta.signed."
  "www.expirado.test."
  "www.ds-roto.test."
  "www.alg-invalido.test."
)

for dom in "${DOMINIOS[@]}"; do
  # Consulta al resolutor validador (172.30.0.101)
  res_val=$(dig @172.30.0.101 +dnssec +time=2 +tries=1 "$dom" A)
  rcode_val=$(echo "$res_val" | grep "status:" | awk '{print $6}' | tr -d ',')
  [ -z "$rcode_val" ] && rcode_val="TIMEOUT"
  ad_val=$(echo "$res_val" | grep -q "flags:.* ad" && echo "SI" || echo "NO")
  
  # Consulta al resolutor inseguro (172.30.0.100)
  res_insec=$(dig @172.30.0.100 +dnssec +time=2 +tries=1 "$dom" A)
  rcode_insec=$(echo "$res_insec" | grep "status:" | awk '{print $6}' | tr -d ',')
  [ -z "$rcode_insec" ] && rcode_insec="TIMEOUT"
  ad_insec=$(echo "$res_insec" | grep -q "flags:.* ad" && echo "SI" || echo "NO")

  # Extraer la IP resuelta (si la hubo)
  ip_res=$(echo "$res_insec" | grep -A 1 "ANSWER SECTION:" | tail -n 1 | awk '{print $NF}')
  [[ "$ip_res" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || ip_res="N/A"

  printf "%-26s | %-12s | %-8s | %-12s | %-8s | %s\n" "$dom" "$rcode_val" "$ad_val" "$rcode_insec" "$ad_insec" "$ip_res"
done
echo "=========================================================================================="
