# igmp-watch

Monitor de pertenencia a grupos multicast IPv4/IPv6 del kernel Linux en tiempo
real (C++23, zero deps).

Lee `/proc/net/igmp` (IGMPv3, grupos IPv4) y `/proc/net/igmp6` (MLDv2, grupos
IPv6) y muestra cada grupo del sistema: dirección en formato legible (el kernel
imprime los grupos IPv4 en **orden de bytes invertido** — `010000E0` →
`224.0.0.1`), número de usuarios locales (sockets suscritos), timer del grupo,
reporter (último pid que reportó) y flags de estado para IPv6 (`TE`, `GS`,
`UNSOL`, `RI`). Decodifica los grupos well-known: `all-hosts`, `all-routers`,
`mDNS`, `mDNSv6`, `LLMNR`, `SSDP`, `IGMP`, `RIP`, `MLDv2`, `VRRP`…
Útil para auditar qué procesos se suscriben a multicast (Avahi/mDNS, SSDP,
UPnP, juegos en LAN), detectar suscripciones inesperadas y ver qué interfaces
participan en el tráfico multicast.

## Features

- **Doble fuente**: `/proc/net/igmp` (IPv4, IGMPv3) + `/proc/net/igmp6` (IPv6, MLDv2)
- **Decodificación de direcciones**: los grupos IPv4 se imprimen en orden de
  bytes invertido (`FB0000E0` → `224.0.0.251`); IPv6 se comprime a notación
  estándar (`ff0200000000000000000000000000fb` → `ff02::fb`)
- **Nombres well-known**: `all-hosts`, `all-routers`, `mDNS`, `mDNSv6`, `LLMNR`,
  `SSDP`, `IGMP`, `RIP`, `MLDv2`… (ocultables con `--no-names`)
- **Flags IPv6 decodificados**: `TE`, `GS`, `UNSOL`, `RI` (0000000C → `UNSOL|RI`)
- **Modo watch (`--watch N`)**: refresh periódico con deltas (grupos
  unidos/abandonados entre snapshots) y flush en cada frame
- **Salida JSON (`--json`)**: `summary` + array `groups` validable con
  `python -m json.tool`
- **Demo mode (`--demo`)**: host sintético (oficina + wifi + docker + LAN
  bridge) con 19 grupos
- **Filtros**: `--iface NAME`, `--v4`/`--v6`, `--users N`, `--top N`
- **`--file`**: parsea un dump de `/proc/net/igmp` (tolera comentarios `#`)
- **`--no-color`**: paleta ANSI mutable (0 códigos en pipes)
- **Selftest**: 69 checks (hex helpers, compresión IPv6, parser v4/v6,
  nombres, filtros, demo, JSON, `/proc` real)

## Build

```bash
g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o igmp-watch
```

## Usage

```bash
# Snapshot único (host real)
./igmp-watch

# Solo IPv6
./igmp-watch --v6

# Solo una interfaz
./igmp-watch --iface eth0

# Grupos con al menos 2 sockets suscritos
./igmp-watch --users 2

# Modo watch (cada 2s) con deltas entre snapshots
./igmp-watch --watch 2

# JSON
./igmp-watch --json

# Demo (host sintético)
./igmp-watch --demo

# Parsear un dump con comentarios
./igmp-watch --file sample-igmp.table --no-color

# Sin colores / sin nombres well-known
./igmp-watch --no-color --no-names

# Auto-tests
./igmp-watch --selftest
```

## Data Source

`/proc/net/igmp` — membresías IGMPv3 por interfaz (formato del kernel):

```
Idx	Device    : Count Querier	Group    Users Timer	Reporter
1	lo        :     1      V3
				010000E0     1 0:00000000		0
```

`/proc/net/igmp6` — membresías MLDv2:

```
idx iface addr(32hex) users flags reporter
1    lo              ff020000000000000000000000000001     1 0000000C 0
```

## License

MIT