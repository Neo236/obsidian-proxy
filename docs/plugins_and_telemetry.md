# Guía del Administrador: Telemetría y Plugins Dinámicos

Obsidian Proxy incluye características avanzadas diseñadas para proporcionar a los administradores control total y observabilidad sobre el enrutamiento de su red, sin necesidad de tocar el código fuente del proyecto en Rust.

## 1. Consumo de Telemetría (API REST)

El proxy expone métricas en tiempo real a través de contadores atómicos (súper eficientes y libres de bloqueos mutex). 

Puedes consultar estas métricas haciendo una petición GET a `/api/stats` en el puerto donde tengas configurada la Web UI (por defecto `3000`).

### Ejemplo de Petición
```bash
curl http://localhost:3000/api/stats
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

El panel Svelte incluido en `obsidian-webui` consume esta API por defecto para dibujar los gráficos en tiempo real.

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
