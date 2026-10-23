<div align="center">
  <h1>Obsidian Proxy</h1>
  <p><strong>Un enrutador L4/L7 de red universal y de alto rendimiento para Minecraft Java y Bedrock, escrito completamente en Rust.</strong></p>
</div>

<br/>

## 🚀 Sobre el Proyecto

**Obsidian Proxy** nace con el objetivo de ser una alternativa moderna, segura y extremadamente eficiente a los proxies tradicionales basados en la Máquina Virtual de Java (como BungeeCord o Velocity). 

Aprovechando el poder de Rust y el ecosistema asíncrono de Tokio, Obsidian es capaz de enrutar decenas de miles de paquetes TCP/UDP concurrentes gastando apenas un puñado de megabytes de RAM, sin los temidos micro-cortes provocados por el Recolector de Basura (Garbage Collector).

### Características Principales

*   ⚡ **Rendimiento Cero-Costo:** Arquitectura asíncrona no bloqueante (Lock-Free) apoyada en primitivas atómicas de Rust.
*   🎮 **Soporte Bidireccional (Java & Bedrock):** Implementación de cero del protocolo `RakNet` (UDP) para túneles Bedrock, junto al protocolo estándar TCP de Java Edition.
*   🛡️ **Seguridad del handshake Java y Borde (`PROXY v2`):** Autenticación centralizada contra Mojang con cifrado AES-128-CFB8 y soporte multi-versión para `LoginStart` y `LoginSuccess` (<= 1.18.2, 1.19–1.20.4, 1.20.5–1.21.1, 1.21.2+). Soporta recepción de cabeceras HAProxy `PROXY protocol` v1/v2 desde nodos de borde de confianza (`trusted_proxies`), aplicando limitación de conexiones y tasa de login por IP real del cliente (`IpGuard`) **después** de desencapsular la cabecera de borde. El reenvío de identidad al backend se elige por servidor:
    *   `none`: para vanilla, Forge y NeoForge (preservando el UUID del backend junto con las skins de Mojang).
    *   `bungeecord`: formato legacy para Paper y Spigot.
    *   `obsidian`: formato propio firmado criptográficamente con **HMAC-SHA256 + timestamp** (`OBSIDIANv1` + `OBSIDIAN_FORWARDING_SECRET`).
    *   `send_proxy_v2 = true`: emisión opcional de cabecera binaria `PROXY protocol v2` saliente hacia el backend.

    > Como todo proxy de Minecraft, los backends deben correr con `online-mode=false`: el proxy ya autenticó contra Mojang y el cliente solo puede hacerlo una vez. Eso implica que los backends **no deben ser alcanzables salvo desde el proxy**.
*   🧩 **Compatibilidad Transparente con Mods:** Parseo y enrutamiento inteligente de marcadores `\0FML\0`, `\0FML2\0`, `\0FML3\0`, `\0NEO` y `\0FORGE`. Total compatibilidad con Forge, NeoForge y Fabric sin corromper conexiones BungeeCord ni firmas HMAC.
*   💤 **Hibernación y Sala de Espera (`Hold`, `Limbo`, `Wake`):** Despertar bajo demanda (`[wake.*]`) con retención activa en estado `Configuration` enviando `Keep Alive (0x04)` y empalme transparente (`Hold`), sala de espera (`Limbo`) con salida automática cuando el backend levanta, o despertar manual desde la API (`POST /api/backends/:name/wake`) y el panel web.
*   📜 **Motor de Plugins Dinámico:** Un intérprete nativo integrado (`Rhai`) permite escribir scripts al vuelo (ej. firewalls, filtros anti-bots) dentro de la carpeta `/plugins`, interceptando conexiones al instante sin necesidad de recompilar Rust.
*   📊 **Telemetría y WebUI Integrada:** Base de datos embebida (SQLite WAL fuera de la ruta caliente) y un panel de administración Single Page Application (Svelte 5) para gestionar backends, modos de reenvío, despertares manuales y tráfico en tiempo real.

### Estado del proyecto

Esta tabla resume qué componentes están disponibles hoy en el binario:

| Componente | Estado |
| --- | --- |
| Framing, compresión (con tope pre-alocación) y cifrado Java (`AES-128-CFB8`) | ✅ En uso |
| Login online-mode contra Mojang (multi-versión `1.7` a `1.21+`) | ✅ En uso |
| Reenvío de identidad: `none`, `bungeecord` y `obsidian` (HMAC-SHA256 + timestamp) | ✅ En uso |
| HAProxy `PROXY protocol` v1/v2 entrante (`trusted_proxies`) y v2 saliente (`send_proxy_v2`) | ✅ En uso |
| Limitador por IP real (`IpGuard`: conexiones concurrentes + logins/min) y timeout en `Play` | ✅ En uso |
| Server List Ping (refleja jugadores reales y salud del backend por virtual host) | ✅ En uso |
| Motor de plugins Rhai (sandbox acotado + fail-closed) | ✅ En uso |
| Panel web y API (`GET/PUT /api/backends`, `POST /api/reload`, `POST /api/backends/:name/wake`) | ✅ En uso |
| Historial de eventos (SQLite WAL asíncrono fuera de la ruta caliente) | ✅ En uso |
| Routing por virtual host y sondas de salud reconciliadas en caliente | ✅ En uso |
| Hibernación de backends (`Hold` activo con KeepAlives, `Limbo`, `Message` y `Wake` manual) | ✅ En uso |
| Bedrock / RakNet (sesiones con TTL, límites de fragmentación/ACK y Zlib acotado) | 🚧 Túnel UDP RakNet operativo; traductor cruzado Java ↔ Bedrock planeado |

---

## 🛠️ Arquitectura Técnica

El proxy está subdividido modularmente en **6 Crates** principales:
1.  `obsidian-core`: El corazón asíncrono y el enrutador L7.
2.  `obsidian-protocol`: El códec de paquetes para Minecraft Java (VarInts, Compresión, Framing).
3.  `obsidian-raknet`: Re-implementación segura del protocolo UDP RakNet, con reensamblaje de fragmentos (protegido contra DoS/OutOfBounds).
4.  `obsidian-bedrock`: Códec de red para Bedrock (Zlib/Snappy) y lógica criptográfica para Xbox Live Auth.
5.  `obsidian-plugins`: Sandbox embebido que evalúa scripts Rhai para interceptar el ciclo de vida de los jugadores (`on_player_join`).
6.  `obsidian-web`: API REST y persistencia local de configuración vía Axum.

---

## 💻 Requisitos y Compilación

Para compilar el proyecto desde su código fuente necesitarás tener instalada la cadena de herramientas de Rust.

```bash
# 1. Clona el repositorio
git clone https://github.com/Neo236/obsidian-proxy.git
cd obsidian-proxy

# 2. Compila el panel web (opcional; el proxy funciona sin el)
cd obsidian-webui && npm ci && npm run build && cd ..

# 3. Compila el proyecto en modo release
cargo build --release

# 4. Ejecuta el proxy
./target/release/obsidian --help
```

### Configuración

Toda la topología vive en `obsidian.toml`: backends, hostnames que rutean a cada uno,
y comandos de arranque. Copiá `obsidian.example.toml` y ajustalo.

```toml
[[backend]]
name = "survival"
addr = "127.0.0.1:25566"
hostnames = ["play.example.com"]
default = true
```

El archivo es opcional — sin él el proxy arranca con un backend en `127.0.0.1:25566`.
Los flags del CLI (`--bind`, `--backend`, `--motd`) siguen funcionando y pisan lo que
diga el archivo para esa ejecución.

El panel de administración escribe sobre este mismo archivo, preservando comentarios y
el resto de las secciones. Si lo editaste a mano mientras el panel estaba abierto, el
guardado responde `409` en vez de pisar tu cambio: recargá y volvé a aplicarlo.

### Panel de administración

El panel escucha en el puerto 3000 y exige un token Bearer. Al arrancar, el proxy
imprime uno generado al azar para esa ejecución:

```
  Admin token: 9f2c...  (generado para esta ejecución)
```

Pegalo en la pantalla de ingreso del panel. Para que sea estable entre reinicios,
definí la variable de entorno antes de arrancar:

```bash
export OBSIDIAN_ADMIN_TOKEN="una-cadena-larga-y-aleatoria"
```

Otras variables opcionales: `OBSIDIAN_WEBUI_DIR` (ubicación del panel compilado) y
`OBSIDIAN_ALLOWED_ORIGIN` (habilita un origen cruzado concreto, por ejemplo un
servidor de desarrollo de Vite). Sin esta última no se permite ningún origen
cruzado.

---

## 📦 Motor de Plugins (Rhai)

Los administradores pueden defender su servidor en tiempo real con archivos de texto plano. Crea la carpeta `plugins/` en la raíz del proxy y añade, por ejemplo, `firewall.rhai`:

```rhai
fn on_player_join(ip, username) {
    // Bloquear a un jugador malicioso por nombre
    if username == "BotMalicioso" {
        return false;
    }

    // Permitir la entrada si pasa todos los checks
    return true;
}
```

---

## 📄 Licencia

Este proyecto está bajo licencia [MIT](LICENSE) - siéntete libre de modificarlo, distribuirlo y mejorarlo.
