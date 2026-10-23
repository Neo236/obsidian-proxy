# Implementación del Protocolo RakNet en Obsidian

Este documento detalla la implementación técnica del protocolo RakNet en el crate `obsidian-raknet`, desarrollado en Rust. El código gestiona de forma robusta las conexiones UDP, la serialización/deserialización de estructuras de red y la mitigación de errores comunes en redes.

## 1. Ping Offline (Offline Ping)
El descubrimiento de servidores en LAN o Internet se maneja en el archivo `offline.rs`. Se utilizan las estructuras `UnconnectedPing` y `UnconnectedPong`.
*   **UnconnectedPing (ID `0x01`)**: Se decodifica leyendo un timestamp de 64 bits (`time`), validando 16 bytes de "Magic" (`MAGIC`) usando la función `check_magic`, y finalmente obteniendo un `client_guid` de 64 bits.
*   **UnconnectedPong (ID `0x1C`)**: Al responder, el servidor inyecta el `time` devuelto, el `server_guid`, la cadena mágica, la longitud en 16 bits del string de identidad (MOTD del servidor) y el propio string convertido a bytes. 

## 2. Peticiones de Conexión
El handshake inicial (Open Connection Sequence) se realiza mediante múltiples paquetes implementados en `offline.rs` y `connection.rs`:
*   `OpenConnectionRequest1` / `OpenConnectionReply1` y `OpenConnectionRequest2` / `OpenConnectionReply2` establecen el tamaño máximo de transmisión (MTU), negocian la versión de protocolo (por defecto manejada como un byte simple) y validan el `client_guid` y `server_guid`.
*   El paquete `ConnectionRequest` (ID `0x09`) maneja las solicitudes orientadas a la conexión en `connection.rs`. Lee el `client_guid`, el tiempo y si se utiliza seguridad (`use_security`).
*   La máquina de estados `RakNetConnection` realiza transiciones explícitas (`Connecting` -> `Connected`) interceptando los IDs `0x10` (`ConnectionRequestAccepted`) y `0x13` (`NewIncomingConnection`).

## 3. Corrección de Inversión de Octetos IPv4
RakNet requiere históricamente que los bytes de las direcciones IPv4 se transmitan en negación bit a bit (*bitwise NOT*) para ciertas respuestas.
En la implementación de `get_address` y `put_address` (`offline.rs`):
*   Al decodificar: `Ipv4Addr::new(!buf.get_u8(), !buf.get_u8(), !buf.get_u8(), !buf.get_u8())`.
*   Al codificar: `buf.put_slice(&v4.ip().octets().map(|b| !b))`.
Esto asegura que los clientes Bedrock interpreten y parseen correctamente las direcciones IP del proxy/servidor al decodificar respuestas como `OpenConnectionReply2`.

## 4. Fragmentación y Reensamblaje de Datagramas
Los datagramas y frames de RakNet están encapsulados con estricto control de memoria.
*   **Datagram (`datagram.rs`)**: Tiene 1 byte de `flags`, seguido de un número de secuencia de 24-bits (`sequence_number`) procesado mediante enmascaramiento y desplazamientos bit a bit (`(b0 | b1 << 8 | b2 << 16)`).
*   **EncapsulatedFrame**: Desempaqueta información de confiabilidad (3 bits) extraída con máscaras (`flags & 0xE0 >> 5`), flags de división y datos de secuencia.
*   **Control de Límites Estricto (`FragmentAssembler` en `fragment.rs`)**: Mantiene un `HashMap` de ensamblajes (`assemblies`). Al recibir un fragmento (`handle_fragment`), la estructura evita los *panics* (comunes cuando actores maliciosos envían un índice de fragmentación fuera de los límites) realizando una validación temprana: 
    ```rust
    if split_count == 0 || split_index >= split_count || split_index >= entry.0.len() {
        return None;
    }
    ```
    Si se recolectan todos los fragmentos correctamente (`all_present`), se reensamblan utilizando `BytesMut::new()` concatenando iterativamente cada porción de memoria extraída de manera segura antes de llamar a `freeze()`.

## 5. Blindaje contra DoS, Canal Confiable y TTL de Sesión
*   **Límites en `AckPacket` y `ReliableOrderedChannel` (`reliability.rs`)**: La decodificación de paquetes ACK/NACK rechaza conteos mayores a `MAX_ACK_RECORDS = 4096` y rangos donde `(end - start) > MAX_ACK_SPAN`, evitando expansión cuadrática de memoria. Asimismo, la cola de paquetes fuera de orden (`out_of_order`) está acotada a `MAX_OUT_OF_ORDER_PACKETS = 2048`.
*   **Ciclo de Vida y TTL de Sesiones (`socket.rs`)**: `RakNetListener` limita la tabla concurrente a `MAX_SESSIONS = 4096`, registra `last_seen: Instant` en cada datagrama recibido (`0x80..=0x8F`), elimina la sesión de inmediato al recibir `DISCONNECTION_NOTIFICATION (0x15)` y ejecuta una tarea recolectora que desaloja sesiones inactivas tras `SESSION_TTL = 30s`.
