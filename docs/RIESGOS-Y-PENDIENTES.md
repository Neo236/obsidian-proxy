# Riesgos y pendientes — revisión externa del 2026-09-12

> **Actualización de cierre (2026-10-19):** Todos los riesgos técnicos y pendientes de protocolo/seguridad listados en este documento fueron resueltos y verificados (184 tests en workspace + `clippy -D warnings` limpio):
> - **PROXY protocol v1/v2 entrante y v2 saliente:** implementado en `obsidian-protocol::proxy_protocol` y `PacketStream::maybe_read_proxy_header`, validado exclusivamente contra `trusted_proxies` y con opción `send_proxy_v2 = true` por backend.
> - **Rate limiting por IP real (`IpGuard`):** evaluado *después* de desencapsular `PROXY v2` (`max_connections_per_ip = 16`, `max_logins_per_ip_per_minute = 30`).
> - **Forwarding propio firmado (`forwarding = "obsidian"`):** protocolo `OBSIDIANv1` firmado con `HMAC-SHA256` + ventana de timestamp (`OBSIDIAN_FORWARDING_SECRET`) y verificación en tiempo constante, además de `none` (con preservación de UUID del backend) y `bungeecord`.
> - **Hibernación completa:** `Hold` activo con KeepAlives y empalme en `Configuration`, `Limbo` con monitoreo de salud del destino y endpoint manual `POST /api/backends/:name/wake` + botón en `obsidian-webui`.
> - **Normativa de binds (`flota-neo236`):** defaults en `127.0.0.1` en `config.rs`, `obsidian.example.toml` y `testbed/docker-compose.yml`.
> - **Hardening Bedrock/RakNet:** límites pre-alocación en Zlib/Snappy y compresión Java, topes de ACK/fragmentación y `SESSION_TTL = 30s` + desconexión `0x15` en `RakNetListener`.

Escrito desde el proyecto de infraestructura (`homelab-fleet`), no desde acá.
El disparador fue una pregunta concreta: **¿sirve Obsidian para que el servidor
de Minecraft vea la IP real de los jugadores?** La respuesta llevó a revisar el
repo entero, y lo que salió excede esa pregunta.

Nada de esto se tocó. Es una lista para cuando se retome.

---

## 0. El contexto que motivó la revisión

El edge de OCI hace DNAT del puerto 25565 hacia el túnel WireGuard, y después
enmascara el origen:

```
chain postrouting {
    oifname "wg0" ct status dnat masquerade comment "servicios crudos: origen -> 10.222.0.1"
}
```

Resultado: **el servidor ve a todos los jugadores como `10.222.0.1`**. No se
puede banear por IP, ni filtrar, ni investigar abuso.

El servidor de producción (`minetuki`) es:

| | |
|---|---|
| Imagen | `itzg/minecraft-server` (digest fijo) |
| Tipo | **NEOFORGE** 1.21.1 (NeoForge 21.1.248) |
| `online-mode` | **true** |
| `prevent-proxy-connections` | false |
| Bind | `10.222.0.2:25565` |
| Memoria | 8 GB |

---

## 1. ¿Obsidian resuelve el problema hoy? No, y por dos motivos distintos

### 1.1 No implementa PROXY protocol entrante

Se buscó en todo el código (`proxy_protocol`, `proxy-protocol`, `haproxy`,
`PROXY TCP`): **cero coincidencias**.

Eso importa porque es exactamente lo que haría falta para que Obsidian sirva
como pieza del edge: si algún día el balanceador o el edge le hablan con PROXY
protocol, Obsidian no sabría leer la cabecera y perdería la IP igual.

> **Pendiente concreto:** aceptar PROXY protocol v1/v2 en el listener de Java.
> Es una cabecera al inicio de la conexión TCP, antes del handshake de
> Minecraft. Hay que decidir además **de qué orígenes se confía** en esa
> cabecera — aceptarla de cualquiera permite que cualquiera declare la IP que
> quiera, que es una suplantación trivial.

### 1.2 NeoForge no puede recibir la IP real por medios nativos

Esto no es una falla de Obsidian: el README ya lo dice bien (`forwarding = none`
para vanilla, Forge y NeoForge). Es una limitación del backend.

| Backend | Reenvío de IP nativo |
|---|---|
| Paper / Spigot | sí — `bungeecord: true`, y además `proxy-protocol` |
| Velocity / BungeeCord (como proxy) | sí |
| **Vanilla / Forge / NeoForge** | **no** |

Para Forge y NeoForge existe el mod **Proxy-Compatible-Forge** (adde0109), que
agrega forwarding moderno de Velocity, BungeeGuard y BungeeCord legacy. O sea:
**sí depende de un mod.** Sin él, ningún proxy —Obsidian, Velocity o
BungeeCord— puede pasarle la IP real a un servidor NeoForge.

⚠️ Además, Forge 1.13+ tiene una incompatibilidad conocida con proxies: falta el
paquete de *reset* de registros al cambiar de backend. Solo afecta a redes con
varios servidores entre los que el jugador salta; para un backend único no
aplica, pero conviene tenerlo escrito antes de diseñar una red.

### 1.3 El costo oculto de meter un proxy de Minecraft

Cualquier proxy de Minecraft —Obsidian incluido— obliga a los backends a correr
con **`online-mode=false`**, porque el proxy ya autenticó contra Mojang y el
cliente solo puede hacerlo una vez. El propio `obsidian.example.toml` lo
advierte.

**Hoy `minetuki` corre con `online-mode=true`.** Adoptarlo implica apagarlo, y
eso convierte al backend en un servidor que acepta a cualquiera que diga
llamarse como quiera. Deja de ser seguro por sí mismo y pasa a depender de que
**nadie más que el proxy pueda alcanzarlo**. Con el bind actual
(`10.222.0.2:25565`, solo túnel) la condición se cumple, pero pasa a ser
**load-bearing**: un error de bind futuro deja el servidor abierto sin
autenticación.

---

## 2. Estado del repositorio: el riesgo más urgente

| | |
|---|---|
| Commits en la historia | **1** (`3818e17` "Initial commit: Obsidian Proxy v1.0") |
| Archivos sin commitear | **64** |
| Diferencia | **+7.350 / −1.293 líneas** |

> **Esto es lo primero que hay que arreglar, antes que cualquier función nueva.**
> Hay más trabajo fuera de la historia de git que dentro. Un `git checkout`
> desafortunado, un disco que falla o un `git clean` distraído se llevan siete
> mil líneas. El repo no está respaldado por su propia historia.

Y como efecto secundario: la revisión de código es imposible. No hay forma de
ver qué cambió, por qué, ni de volver atrás un cambio puntual.

**Sugerencia:** partir esos 64 archivos en commits temáticos (config, routing,
eventos, bedrock, plugins, testbed, CI) antes de seguir. No hace falta que sea
perfecto; hace falta que exista.

---

## 3. Lo que está bien, y conviene no romper

No todo son pendientes. Lo verificado:

- **11.392 líneas de Rust** con **170 tests** (`#[test]` / `#[tokio::test]`).
  Para un proyecto de una persona, es una proporción sana.
- **CI en GitHub Actions** con `RUSTFLAGS: -D warnings`, `cargo fmt --check` y
  `cargo clippy --workspace --all-targets --all-features`, en **ubuntu y
  windows**. La disciplina está puesta.
- **El sandbox de Rhai tiene límites explícitos**, no confianza ciega:
  `MAX_OPERATIONS = 100.000`, `MAX_CALL_LEVELS = 32`,
  `MAX_STRING_SIZE = 8 KB`, más topes de arrays, mapas y profundidad de
  expresiones. Y es *fail-closed*: si un plugin no carga, lo dice fuerte en vez
  de seguir como si nada.
- **El panel web bindea a `127.0.0.1` por defecto**, con el razonamiento escrito
  al lado (puede reescribir la configuración, así que llegar a él debería exigir
  estar en la máquina). Es exactamente el criterio correcto.
- **El testbed no toca producción**: puertos 2557x, `restart: "no"`, y un
  comentario que lo dice explícito. Bien pensado.
- **El README distingue lo implementado de lo que no**, con una tabla de estado.
  Es honesto y poco común.

---

## 4. Pendientes ordenados por lo que costaría descubrirlos tarde

### 4.1 El ejemplo de configuración viola la normativa de la flota

```toml
[proxy]
bind = "0.0.0.0:25565"
raknet_bind = "0.0.0.0:19132"
```

`NORMATIVA.md` de la flota es explícita: **nada se bindea a `0.0.0.0`**, porque
queda expuesto a toda la LAN y a todo el tailnet a la vez, y **UFW no lo tapa si
el puerto lo publica Docker**. Siete servicios de esta flota ya cayeron en eso.

Si Obsidian se despliega acá, el bind tiene que ser la IP del túnel
(`10.222.0.2`) o loopback. Conviene que **el ejemplo enseñe lo correcto**, con
`127.0.0.1` por defecto y una nota, igual que ya hace la sección `[web]`.

### 4.2 Verificar que el CI corra los tests

Se leyeron las primeras 40 líneas del workflow: están `fmt` y `clippy`.
**No se alcanzó a ver un paso `cargo test`.** Si no está, 170 tests no se
ejecutan en CI y solo sirven cuando alguien se acuerda de correrlos.

### 4.3 Funciones anunciadas que no existen todavía

El README ya las marca, y está bien que lo haga. Repetidas acá para que no se
pierdan:

| Componente | Estado declarado |
|---|---|
| Velocity Modern Forwarding | 🚧 no implementado |
| Bedrock / RakNet | 🚧 handshake offline; **el túnel no funciona** |
| Hibernación de backends | ⚠️ despierta y avisa; limbo y retención pendientes |

El riesgo no es técnico sino de expectativa: el README de portada vende Bedrock
como característica principal (*"Soporte Bidireccional"*) y la tabla de estado,
más abajo, dice que el túnel no anda. **Alguien que lea solo la portada va a
desplegarlo esperando Bedrock.** Conviene que la limitación suba a la portada.

### 4.4 El reenvío `bungeecord` no lleva prueba de origen

El propio ejemplo lo dice: *"`bungeecord` no lleva ninguna prueba de haber
salido de acá"*. Es cierto de BungeeCord legacy en general, no un defecto de
Obsidian — pero significa que **la seguridad depende enteramente de que el
backend sea inalcanzable salvo desde el proxy**. Si algún día se implementa
forwarding moderno de Velocity o BungeeGuard, eso deja de ser así (llevan
secreto compartido o firma).

Vale la pena que sea lo próximo después de PROXY protocol, porque es lo que
convierte "seguro si la red está bien" en "seguro".

---

## 5. Si se retoma con la mira puesta en el edge

Orden sugerido, del que más desbloquea al que menos:

1. **Commitear los 64 archivos.** Todo lo demás es construir sobre arena.
2. **Confirmar que el CI corra `cargo test`.**
3. **PROXY protocol entrante**, con lista de orígenes de confianza.
4. **Forwarding moderno** (Velocity o BungeeGuard) para no depender de la
   topología de red como única defensa.
5. Recién ahí, decidir si el servidor NeoForge lleva
   **Proxy-Compatible-Forge** — sin eso, la IP real llega al proxy y muere ahí.
6. Cambiar el ejemplo a un bind que no sea `0.0.0.0`.

---

## 6. La alternativa que no necesita nada de esto

Para dejarla anotada al lado, porque resuelve el problema original sin proxy de
Minecraft: **quitar el `masquerade` del edge y devolver las respuestas por
ruteo de política** en server0 (marcar la conexión entrante y forzar que la
respuesta salga por `wg0`). La IP real llega al servidor sin mods, sin
`online-mode=false` y sin una pieza nueva en el camino.

Es menos flexible —no da enrutamiento por hostname, ni plugins, ni hibernación—
pero si lo único que se busca es que el servidor vea la IP del jugador, es el
camino corto. Obsidian se justifica por lo otro que hace, no por esto.
