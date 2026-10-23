# Arquitectura de Obsidian

## Componentes del Sistema
Obsidian es un proxy propio para Minecraft escrito en Rust y dividido en 7 crates:
- **obsidian-core**: Contiene el enrutador asíncrono (`ConnectionRouter`), la tabla de ruteo sin bloqueos (`SharedRouting`), el monitor de salud (`HealthMonitor`), el supervisor de arranque bajo demanda (`WakeSupervisor`), el almacén de configuración en caliente (`ConfigStore`) y el historial de eventos (`EventLog`).
- **obsidian-protocol**: Implementa el framing de paquetes de Minecraft Java, VarInt/VarLong, compresión Zlib, criptografía (`RSA`, `AES-128-CFB8`), `PROXY protocol` v1/v2 y paquetes multi-versión de `Handshake`, `Status` y `Login`.
- **obsidian-raknet**: Implementa el protocolo UDP RakNet con control de fragmentación, canales ordenados confiables y límites de memoria por sesión.
- **obsidian-bedrock**: Implementa el framing de lotes (`Zlib` y `Snappy`) y las estructuras base de login para Bedrock Edition.
- **obsidian-plugins**: Sandbox embebido en Rhai con límites estrictos de operaciones y memoria (`fail-closed`).
- **obsidian-web**: API REST autenticada con token Bearer (comparación en tiempo constante) y servidor estático para el panel `obsidian-webui`.
- **obsidian-cli**: Punto de entrada de línea de comandos que carga `obsidian.toml`, aplica overrides de CLI y arranca el proxy y el panel web.

## Enrutamiento Asíncrono (L7 Stateful con Tokio)
El enrutador (`ConnectionRouter` en `crates/obsidian-core/src/router.rs`) gestiona las conexiones entrantes bajo un presupuesto estricto de negociación (`negotiation_timeout_secs`), un timeout de inactividad en juego (`play_idle_timeout_secs`), un semáforo global (`MAX_CONCURRENT_CONNECTIONS`) y un guardián por IP (`IpGuard`):
- **PROXY Protocol Entrante (`trusted_proxies`)**: Si la IP del socket pertenece a `trusted_proxies`, Obsidian lee y valida una cabecera HAProxy `PROXY` v1 o v2 al inicio del stream TCP (soportando IPv4, IPv6, IPv4-mapeado en IPv6, comando `LOCAL` para health checks y extensiones TLV) para recuperar la IP real del jugador antes del Handshake.
- **Limitador por IP Real (`IpGuard`)**: Inmediatamente después de resolver la IP real del cliente (post-`PROXY v2`), `IpGuard` aplica un tope de conexiones simultáneas por IP (`max_connections_per_ip`, por defecto `16`) mediante un permiso RAII (`IpConnectionPermit`) y un tope de intentos de login por minuto (`max_logins_per_ip_per_minute`, por defecto `30`) en ventana móvil de 60 segundos antes de gastar CPU en RSA o llamadas a Mojang.
- **Status (Server List Ping)**: Se responde localmente consultando el estado real (`Health::Up`, `Health::Down`, `Health::Starting`) del backend correspondiente al virtual host solicitado.
- **Login Centralizado y Multi-Versión**: Obsidian termina el cifrado RSA + `AES-128-CFB8`, autentica al jugador contra Mojang Session Server, ejecuta los hooks de plugins Rhai en un hilo bloqueante con timeout, y negocia el login contra el backend seleccionado adaptando el formato de `LoginStart` y `LoginSuccess` a la versión de protocolo del cliente (`<= 1.18.2`, `1.19..=1.20.4`, `1.20.5..=1.21.1`, `1.21.2+`).

## Modos de Reenvío al Backend (`Forwarding` y `send_proxy_v2`)
Cada backend define su modo de reenvío en `obsidian.toml`:
- **`none` (por defecto)**: Envía el hostname limpio (preservando marcadores de modloader como `\0FML\0`, `\0FML2\0`, `\0FML3\0`, `\0NEO`, `\0FORGE`). Ideal para servidores vanilla, Forge y NeoForge. Obsidian captura el UUID asignado por el backend en su `LoginSuccess` y se lo entrega al cliente junto con las propiedades de skin firmadas por Mojang, evitando discrepancias de UUID de entidad.
- **`bungeecord`**: Inyecta `\0<Client_IP>\0<Client_UUID>\0<Properties_JSON>` en el `Handshake` hacia el backend (compatible con Paper/Spigot con `bungeecord: true`). Cualquier intento del cliente de inyectar campos separados por `\0` en el hostname original es rechazado antes de contactar al backend.
- **`obsidian` (Propia firmada con HMAC-SHA256)**: Inyecta `\0OBSIDIANv1\0<Client_IP>\0<Client_UUID>\0<Properties_JSON>\0<Timestamp_Secs>\0<HMAC_Hex>` firmado con el secreto compartido en `OBSIDIAN_FORWARDING_SECRET` (`forwarding_secret_env`) y verificable en tiempo constante mediante `Handshake::verify_obsidian_forwarding`.
- **`send_proxy_v2 = true` (Opcional por backend)**: Antepone una cabecera binaria HAProxy `PROXY protocol v2` (`encode_proxy_v2`) con el `SocketAddr` real del cliente al abrir la conexión TCP hacia el backend, permitiendo preservar la IP real a nivel de transporte (L4) incluso con `forwarding = "none"`.

## Salud Dinámica e Hibernación (`HealthMonitor` y `WakeSupervisor`)
- **`HealthMonitor`**: Sondea periódicamente cada backend por TCP y actualiza su `HealthCell` en `SharedRouting`. Su bucle supervisor reconcilia automáticamente las tareas de sondeo cuando se agregan, eliminan o cambian backends mediante `/api/reload` o `/api/backends`.
- **`WakeSupervisor` y Estrategias de Espera**: Cuando un jugador intenta entrar a un backend en reposo con `wake` configurado y `wake_on_connect = true`, dispara el comando definido en `[wake.<nombre>]` de forma idempotente (un solo proceso por backend) y aplica la primera estrategia aplicable:
  - **`hold` (`>= 1.20.2`)**: Pasa al cliente al estado `Configuration`, envía paquetes `Clientbound Keep Alive (0x04)` periódicos, almacena los paquetes de configuración iniciales del cliente y, en cuanto el backend pasa a `Health::Up`, conecta y empalma la sesión sin que el jugador tenga que reconectar.
  - **`limbo`**: Enruta al jugador al backend de sala de espera configurado mientras monitorea la salud del backend destino, finalizando la sesión de limbo apenas el servidor destino está listo.
  - **`message`**: Informa al jugador que el servidor está arrancando junto con el tiempo estimado (`ready_timeout_secs`).
  - **Despertar Manual (`POST /api/backends/:name/wake`)**: Permite despertar desde el panel web o la API aquellos backends con `wake_on_connect = false`.

## Configuración Declarativa (`ConfigStore`) e Historial (`EventLog`)
- **`ConfigStore`**: Edita `obsidian.toml` de forma atómica usando `toml_edit` para preservar comentarios y secciones (`[proxy]`, `[web]`, `[wake.*]`), protegiendo contra escrituras concurrentes mediante huella digital (`409 Conflict` / `StaleWrite`).
- **`EventLog`**: Registra transiciones de salud, despertares, recargas y rechazos en SQLite (`WAL`) en un hilo dedicado conectado por un canal acotado, sin bloquear jamás la ruta de paquetes.
