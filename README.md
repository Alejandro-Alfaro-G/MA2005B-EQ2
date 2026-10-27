# Laboratorio Experimental DNSSEC con BIND 9 y Docker

Infraestructura jerárquica DNS completa desplegada sobre microservicios en Docker, diseñada para auditar la cadena de confianza, parámetros de RFCs (4033-4035, 8624, 9276), vectores de enumeración (NSEC vs NSEC3) y estados *Bogus*.

## Requisitos Previos
* Docker Engine y Docker Compose v2.
* Python 3 con `dnspython` y `cryptography`:
  ```bash
  sudo apt install -y python3-dnspython python3-cryptography dnsutils
  ```

## Despliegue Rápido (3 Pasos)

1. **Levantar los contenedores de la red:**
   ```bash
   docker compose up -d
   ```

2. **Generar llaves criptográficas y firmar el árbol (Bottom-Up):**
   ```bash
   bash scripts/01_generar_llaves_y_firmar.sh
   ```

3. **Ejecutar la suite de pruebas:**
   ```bash
   # Evaluación rápida en consola
   bash scripts/03_run_eval_presentacion.sh

   # Auditoría de RFCs y análisis criptográfico
   python3 scripts/02_auditor_dnssec.py
   ```

## Topología de Zonas y Escenarios de Prueba

| Dominio | Configuración Criptográfica | Estado Esperado (Validador) |
| :--- | :--- | :--- |
| `beta.signed` | ECDSA P-256 (13) + NSEC3 | `NOERROR` con bandera `AD` |
| `delta.signed` | ECDSA P-256 (13) + NSEC (Plano) | `NOERROR` con `AD` (Vulnerable a Zone Walking) |
| `epsilon.signed`| RSA-SHA256 (8) + NSEC3 | `NOERROR` con bandera `AD` |
| `gamma.signed` | Sin firmas / Sin DS | `NOERROR` sin bandera `AD` (Inseguro) |
| `ds-roto.test` | DS alterado en padre (KeyTag 65000) | `SERVFAIL` (Cadena Rota / *Bogus*) |
| `expirado.test`| Firmas RRSIG con ventana de 2025 | `SERVFAIL` (Firma Caducada) |
| `alg-invalido.test`| RSASHA1 (5) | `NOERROR` con `AD` (Alerta RFC 8624) |
