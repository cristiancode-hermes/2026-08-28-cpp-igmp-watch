# igmp-watch — Architecture

## Flujo

```
/proc/net/igmp  ──► parse_igmp_file()  ──┐
                                         ├──► std::vector<Group> (v4 + v6)
/proc/net/igmp6 ──► parse_igmp6_file() ──┘            │
                                                      ▼
                                            stable_sort (proto, iface, addr)
                                                      │
                                          ┌───────────┴───────────┐
                                          ▼                       ▼
                                   render_snapshot()       render_json()
                                          │
                       filtros (iface/proto/users/top) → watch delta
```

## Decisiones técnicas

- **Monolítico stdlib-only**: un solo TU, `g++ -std=c++23` directo, zero
  dependencias (`<charconv>` para parseo, `<algorithm>` para sort).
- **Orden de bytes IPv4**: `/proc/net/igmp` imprime los grupos en orden
  INVERTIDO (`010000E0` = 224.0.0.1). `fmt_ipv4()` revierte los 4 bytes antes
  de formatear. Verificado contra hosts reales (eth0/lo muestran all-hosts).
- **Compresión IPv6**: `fmt_ipv6()` convierte 32 hex chars a 8 words de 16
  bits, localiza la run más larga de words cero (≥2) y la comprime con `::`.
  Pitfall resuelto: tras emitir `::`, el separador `:` del grupo siguiente debe
  suprimirse (`skip_sep`), o se produce `ff02:::1`.
- **Doble parser con heurística**: el formato de `/proc/net/igmp` mezcla líneas
  de interfaz (`idx dev : count querier`) y de grupo (8 hex + users + timer
  `secs:jiffies` + reporter). El discriminador es el token `:` standalone en
  posición 2 de la línea de interfaz (el timer `0:00000000` NO se confunde
  porque no es un token independiente).
- **Dumps tolerantes**: `--file` y los parsers saltan comentarios `#`, líneas
  vacías, cabeceras (`Idx`/`idx`) y filas malformadas.
- **Flags IPv6**: `/proc/net/igmp6` columna 5 en hex; se decodifican los bits
  conocidos (0x1 TE, 0x2 GS, 0x4 UNSOL, 0x8 RI).
- **Paleta ANSI mutable**: `--no-color` vacía las strings de color en runtime
  (no `constexpr`) — afecta por igual a selftest, watch y snapshot
  (verificado: `--no-color | cat -v | grep -c '\^['` → 0).
- **Watch flush**: `render_delta()` termina con `std::cout << std::flush` para
  que `timeout 4 ./igmp-watch --watch 1 > log` nunca pierda frames.