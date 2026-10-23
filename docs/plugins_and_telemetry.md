# Guía del Administrador: Telemetría y Plugins Dinámicos

Obsidian Proxy incluye características avanzadas diseñadas para proporcionar a los administradores control total y observabilidad sobre el enrutamiento de su red, sin necesidad de tocar el código fuente del proyecto en Rust.

## 1. Consumo de Telemetría (API REST)

El proxy expone métricas en tiempo real a través de contadores atómicos (súper eficientes y libres de bloqueos mutex). 

Puedes consultar estas métricas haciendo una petición GET a `/api/stats` en el puerto donde tengas configurada la Web UI (por defecto `3000`).

### Ejemplo de Petición
```bash
curl -H "Authorization: Bearer $OBSIDIAN_ADMIN_TOKEN" http://127.0.0.1:3000/api/stats
```

### Formato de Respuesta JSON
```json
{
  "active_connections": 12,
  "total_bytes_rx": 45012344,
  "total_bytes_tx": 89012344
}
```

*   `active_connections`: Número de jugadores simultáneos actualmente siendo enrutados (tanto Java como Bedrock L7).
*   `total_bytes_rx`: Total de bytes recibidos por el proxy desde el inicio del servidor.
*   `total_bytes_tx`: Total de bytes transmitidos por el proxy desde el inicio del servidor.

El panel Svelte incluido en `obsidian-webui` consume esta API por defecto para dibujar las métricas en tiempo real.

### Otros Endpoints de Administración (Autenticados con `Bearer $OBSIDIAN_ADMIN_TOKEN`)
*   `GET /api/backends`: Lista los backends declarados junto con su estado de salud en vivo (`up`, `down`, `starting`, `unknown`), configuración de hibernación (`wake`, `wake_on_connect`, `waiting`, `limbo`) y modo de reenvío (`none`, `bungeecord`, `obsidian`, `send_proxy_v2`).
*   `PUT /api/backends`: Reemplaza la lista de backends en `obsidian.toml` de forma atómica preservando comentarios y recarga la tabla de ruteo en caliente. Devuelve `409 Conflict` si el archivo fue editado manualmente en disco desde la última lectura.
*   `POST /api/reload`: Relee y valida `obsidian.toml` desde disco, actualiza la huella digital de `ConfigStore` y publica la nueva tabla de ruteo en caliente.
*   `POST /api/backends/:name/wake`: Dispara manualmente el comando `[wake.*]` asociado a un backend en hibernación.
*   `GET /api/events?limit=50`: Devuelve el historial reciente de eventos registrado en SQLite.

---

## 2. Escribiendo tu primer Plugin (Rhai)

Obsidian cuenta con un motor de scripting impulsado por **Rhai** incrustado directamente en el enrutador L7. Esto permite filtrar y ejecutar lógica condicional sobre las conexiones en el momento exacto en que un jugador intenta iniciar sesión.

### ¿Dónde colocar los scripts?
Crea una carpeta llamada `plugins` en el directorio raíz desde donde ejecutas el binario de `obsidian-cli`. El `PluginManager` leerá todos los archivos con extensión `.rhai` al iniciar.

### El Hook `on_player_join`

El proxy buscará y evaluará en tus scripts la función `on_player_join(ip, username)`. Esta función **debe** devolver un valor booleano (`true` o `false`).
*   Si devuelve `true`, la conexión continúa.
*   Si devuelve `false`, la conexión es abortada inmediatamente (kick).

### Ejemplo: Filtro Anti-Bots y Baneos

Guarda el siguiente código en `plugins/firewall.rhai`:

```rhai
fn on_player_join(ip, username) {
    // 1. Bloquear a un jugador malicioso por nombre
    if username == "NotchHack" {
        print("Bloqueando intento de conexión del jugador malicioso: " + username);
        return false;
    }

    // 2. Bloquear subredes sospechosas (ej. 192.168.1.x)
    if ip.starts_with("192.168.1.") {
        print("IP " + ip + " bloqueada por reglas de firewall.");
        return false;
    }

    // Permitir la entrada si pasa todos los checks
    print("Permitiendo ingreso a: " + username + " desde " + ip);
    return true;
}
```

### Consideraciones de Rendimiento
Rhai está altamente optimizado. El código es compilado a un AST (Árbol de Sintaxis Abstracta) una sola vez al arrancar el servidor. La ejecución por cada intento de inicio de sesión toma escasos microsegundos, lo que significa que puedes añadir docenas de comprobaciones sin afectar la latencia (ping) de los jugadores reales.

### Límites de ejecución

Los scripts corren en la ruta de login, así que el motor está acotado en todos los ejes que Rhai expone:

| Límite | Valor |
| --- | --- |
| Operaciones interpretadas por invocación | 100 000 |
| Profundidad de llamadas anidadas | 32 |
| Tamaño máximo de string | 8 KB |
| Elementos por array o mapa | 1024 |
| Deadline de reloj para el hook completo | 2 s |

Además, la resolución de módulos está deshabilitada: un script no puede hacer `import` de código que esté en otra parte del disco.

El hook se ejecuta en un hilo bloqueante, no sobre un worker asíncrono, para que un script lento no frene al resto de las conexiones.

### Qué pasa cuando un script falla

**Un fallo deniega la conexión.** Si `on_player_join` lanza una excepción, excede un límite o el hook supera el deadline, el jugador es rechazado. Esto es deliberado: un firewall que deja pasar cuando se rompe deja de ser un firewall.

Las dos únicas situaciones que *no* deniegan son:

- El script no define `on_player_join` en absoluto — simplemente no participa de este hook.
- El script no compila al arrancar. En ese caso nunca se consulta, y el arranque lo reporta por `stderr` para que no creas que tenés un filtro activo cuando no lo tenés.
