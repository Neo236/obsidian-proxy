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
*   🚧 **Soporte Bidireccional (Java & Bedrock):** Implementación sólida para Java Edition. (NOTA: El proxy L7 de Bedrock / RakNet se encuentra actualmente en fase *Work-In-Progress* y su stack de confiabilidad no está totalmente conectado).
*   🛡️ **Modern Forwarding & Seguridad:** Autenticación criptográfica AES-128-CFB8 para Java.
*   🧩 **Compatibilidad Transparente con Mods:** Parseo y enrutamiento inteligente del sufijo oculto `\0FML\0`. ¡Total compatibilidad con Forge, NeoForge y Fabric sin corromper conexiones BungeeCord!
*   📜 **Motor de Plugins Dinámico:** Un intérprete nativo integrado (`Rhai`) permite escribir scripts al vuelo (ej. firewalls, filtros anti-bots) dentro de la carpeta `/plugins`, interceptando conexiones al instante sin necesidad de recompilar Rust.
*   📊 **Telemetría y WebUI Integrada:** Base de datos embebida (SQLite WAL protegido vía `spawn_blocking`) y un panel de administración Single Page Application (Svelte) para monitorear el ancho de banda del servidor en tiempo real.

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
git clone https://github.com/tu-usuario/obsidian-proxy.git
cd obsidian-proxy/obsidian

# 2. Compila el proyecto en modo release (altamente optimizado)
cargo build --release

# 3. Ejecuta el proxy
./target/release/obsidian-cli
```

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
