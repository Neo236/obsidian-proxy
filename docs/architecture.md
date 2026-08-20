# Arquitectura de Obsidian

## Componentes del Sistema
Obsidian es un proxy universal para Minecraft que se divide en varias cajas (crates) principales:
- **obsidian-core**: Contiene el enrutador asíncrono, la lógica de conexión y administración del ciclo de vida de la sesión (ej. `HibernateManager`).
- **obsidian-protocol**: Implementa los paquetes de Minecraft, criptografía (RSA, AES) y manejo de estados (Handshake, Status, Login).
- **obsidian-cli**: Interfaz de línea de comandos que inicializa y levanta el proxy.
- **obsidian-web**: Panel de administración web.

## Enrutamiento Asíncrono (L4/L7 con Tokio)
El enrutador (`ConnectionRouter` en `router.rs`) se basa en `tokio` para manejar múltiples conexiones concurrentes sin bloqueo. Dependiendo de las necesidades de la conexión, utiliza dos estrategias:
- **Enrutamiento L4 (Fast-Path)**: Si la conexión no necesita alteración en la capa de aplicación, el proxy utiliza `tokio::io::copy_bidirectional` para transferir bytes de manera directa y bidireccional entre el cliente y el servidor backend de forma muy eficiente.
- **Enrutamiento L7 (Stateful)**: Si la conexión necesita manipular paquetes (como autenticación o BungeeCord/Velocity IP forwarding), el enrutador inspecciona y descifra los paquetes utilizando `PacketStream`. Aquí maneja las etapas de `LoginStart`, cifrado (EncryptionRequest/Response), compresión de paquetes y autenticación con Mojang. En Bedrock, se establece un túnel UDP de extremo a extremo mediante `RakNetClient`, gestionando la sesión para inspección y reenvío asíncrono.

## BungeeCord IP Forwarding
En el enrutamiento L7, Obsidian implementa BungeeCord IP Forwarding para transmitir la IP real y el perfil (UUID y propiedades) del cliente al servidor de destino.
Esto se hace en el paquete `Handshake` hacia el backend, donde se concatena la dirección de destino con `\0<Client_IP>\0<Client_UUID>\0<Properties_JSON>`. Luego de enviar este Handshake modificado y un paquete de `LoginStart` al backend, Obsidian consume la respuesta de autenticación del backend (como `SetCompression` y `LoginSuccess`) antes de entrar en un bucle continuo de reenvío bidireccional de paquetes (Play-state).

## Ciclo de Vida de la Sesión y Transiciones de Estado
1. **Handshake**: El cliente envía información sobre el protocolo, dirección y el estado siguiente (`NextState`).
2. **Status (Ping)**: Si el cliente solicita el estado (`NextState::Status`), Obsidian responde localmente (`handle_status`) con el MOTD, la versión y la información del servidor sin conectarse al backend, ahorrando recursos.
3. **Login**: Si es un inicio de sesión (`NextState::Login`), el flujo es interceptado (L7) para autenticación con los servidores de sesión de Mojang, activación del cifrado y compresión antes de conectar al backend, o bien se usa la vía rápida L4.
4. **Play**: Una vez que el inicio de sesión es exitoso, los paquetes fluyen en ambas direcciones hasta que alguna de las partes cierre la conexión.

## HibernateManager
El módulo de hibernación de `obsidian-core` incluye el `HibernateManager`, que sirve para administrar el estado de los servidores en reposo. Usa atómicos (`AtomicBool`) para evitar levantar un servidor varias veces a la vez. Cuando un servidor finaliza su secuencia de arranque o ya está disponible de manera confirmada, se invoca `mark_online()`, lo cual restablece el estado `is_waking` a `false`, indicando que el proxy ya no tiene que iniciar el proceso de despertar al servidor backend porque ya está listo para recibir conexiones.

## Inicialización de ServerConfig (CLI)
En `crates/obsidian-cli/src/main.rs`, el proxy se inicializa a través de `clap`. Los argumentos como `--bind`, `--backend`, y `--motd` son recolectados por la estructura `Cli`. Esta información luego se mapea directamente a un `obsidian_core::ServerConfig`, permitiendo configurar las direcciones de escucha para Java (`bind_addr`), Bedrock (`raknet_bind_addr`), y la dirección del backend (`backend_addr`). Esta configuración se inyecta utilizando `ObsidianServer::with_config(config)` antes de ejecutar `server.run()`.

## Telemetría Libre de Bloqueos (Lock-Free)
El núcleo cuenta con una estructura global `ProxyStats` (`obsidian-core/src/stats.rs`) inyectada a través de `Arc`. Esta estructura alberga contadores `AtomicUsize` para registrar el ancho de banda (`total_bytes_rx`, `total_bytes_tx`) y las `active_connections`. Los hilos asíncronos del enrutador incrementan estos contadores utilizando `Ordering::Relaxed`, eliminando la necesidad de `Mutex` y permitiendo que la API REST consuma estos datos en tiempo real sin entorpecer el flujo de paquetes de Minecraft.

## Sistema de Plugins Dinámicos (Rhai)
La expansión de modularidad se introdujo a través del crate independiente `obsidian-plugins`. Este módulo integra un motor de scripting en lenguaje **Rhai**. Al inicializarse `ObsidianServer`, el `PluginManager` compila y cachea todos los scripts `.rhai` presentes en la carpeta de ejecución. Durante el enrutamiento L7 (inmediatamente después del paquete `LoginStart`), el enrutador invoca el "hook" `on_player_join(ip, username)`, permitiendo a los scripts abortar dinámicamente conexiones maliciosas sin recompilar el proxy.

## Panel Web y Protección de Base de Datos
El componente `obsidian-web` utiliza SQLite como motor de base de datos. Dado que SQLite es bloqueante, las consultas a la base de datos se delegan mediante `tokio::task::spawn_blocking`. Esta protección multihilo evita que las operaciones pesadas de E/S de la base de datos bloqueen los hilos de ejecución principales del enrutador. La Interfaz Gráfica (SPA) compila Svelte y consume tanto las rutas CRUD de administración como el nuevo endpoint `/api/stats` para telemetría en tiempo real.
