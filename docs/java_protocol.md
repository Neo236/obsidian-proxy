# Protocolo de Java Edition - Implementación en Obsidian (Rust)

Este documento detalla la implementación técnica del protocolo de Minecraft Java Edition dentro de la base de código `obsidian-protocol`, escrita en Rust. Se analizan aspectos fundamentales como el particionado de tramas (framing), la serialización de tipos dinámicos (`VarInt`), las secuencias de Handshake y Login, Server List Ping (SLP), y las correcciones criptográficas aplicadas en la capa de cifrado.

## 1. Framing del Protocolo (Java Edition)
El protocolo de Minecraft opera sobre una capa de transporte TCP (o conexiones cifradas/comprimidas), donde cada paquete se encapsula en una trama estructurada secuencialmente. 

La estructura básica de una trama en disco/red es:
- **Packet Length (VarInt):** Longitud total en bytes del `Packet ID` sumado al `Payload`.
- **Packet ID (VarInt):** Identificador del tipo de paquete, dependiente del estado actual de la conexión.
- **Payload (Bytes):** Datos brutos del paquete.

La implementación en `obsidian-protocol` (en `src/frame.rs`) utiliza `bytes::BytesMut` y `tokio` para las lecturas asíncronas de flujos. La estructura `PacketFrame` abstrae esta representación y provee soporte nativo para compresión y cifrado "al vuelo". 
Para evitar ataques de denegación de servicio (DoS) por saturación de memoria, la decodificación en `decode_frame_limited` limita el tamaño máximo de paquete permitido (por defecto `MAX_PACKET_SIZE` de 2 MB).

## 2. Decodificación de VarInt y VarLong
Los tipos `VarInt` (32 bits) y `VarLong` (64 bits) utilizan codificación **LEB128** (Little Endian Base 128) para ahorrar ancho de banda. 

En `src/varint.rs`, el algoritmo procesa flujos de bytes de manera continua:
- Lee un byte.
- Extrae los 7 bits menos significativos (`b & 0x7F`) y los desplaza (`<< shift`) hacia la posición correspondiente.
- Verifica el bit más significativo (MSB, `b & 0x80`). Si es `0`, indica el último byte de la secuencia; si es `1`, la lectura continúa.

Para mantener la integridad, existen límites estrictos de procesamiento: un máximo de **5 bytes para VarInt** y **10 bytes para VarLong**. Exceder estos límites dispara un error `VarIntError::VarIntTooLong`. Las cadenas de texto (Strings) se componen de un prefijo de longitud `VarInt` seguido de datos codificados en UTF-8, donde también se verifica que no excedan el límite de caracteres máximo definido para evitar desbordamientos.

## 3. Secuencia de Handshake
El flujo inicial de conexión comienza con el estado **Handshake** (0x00).
El paquete incluye:
- `protocol_version` (VarInt).
- `server_address` (String, máx 32767).
- `server_port` (u16).
- `next_state` (VarInt): `1` para Status o `2` para Login (`3` para Transfer).

En `src/handshake.rs`, se efectúa un análisis (parsing) avanzado sobre `server_address`. Si la cadena contiene caracteres nulos `\0`, extrae información sobre el *modloader* (por ejemplo, identificadores como `FML`, `FML2`, `FML3`, `NEO`, `FORGE`) e información de IP Forwarding de proxies tipo BungeeCord, preservando la dirección limpia (clean address) en memoria y almacenando el sufijo modificado (`fml_marker`). 

**Soporte Transparente de Mods:** Al reconectar al jugador con el servidor destino, el enrutador L7 ensambla la nueva IP Forwarding y concatena limpiamente el `fml_marker` recuperado al final de la cadena de conexión. Esto evita la corrupción del *handshake* de BungeeCord y garantiza que los servidores reconozcan correctamente a los clientes utilizando *modpacks*.

## 4. Secuencia de Login Multi-Versión
Si el siguiente estado solicitado es Login (`2`) o Transfer (`3`), la conexión transiciona a la fase de autenticación y cifrado (definida en `src/login.rs`):

1. **Serverbound Login Start (0x00):** El cliente envía su nombre de usuario (`name`) y, según la versión del protocolo, banderas de firma o `player_uuid`. `LoginStart::encode_for_version` adapta el layout para `<= 1.18.2` (`< 759`), `1.19` (`759`), `1.19.1–1.19.2` (`760`), `1.19.3–1.20.1` (`761..=763`) y `1.20.2+` (`>= 764`).
2. **Clientbound Encryption Request (0x01):** El proxy responde con su `server_id`, la clave pública RSA (`public_key`) en formato SPKI DER, y un `verify_token` generado aleatoriamente.
3. **Serverbound Encryption Response (0x01):** El cliente cifra el secreto compartido (`shared_secret`) y el `verify_token` recibido utilizando la clave pública RSA. Las respuestas firmadas con clave de perfil (`salt`/`signature` de 1.19–1.19.2) se rechazan explícitamente por seguridad.
4. Tras validar el token, activar `AES-128-CFB8` en el flujo y verificar la sesión contra Mojang (`hasJoined`), Obsidian conecta al backend (anteponiendo opcionalmente una cabecera binaria `PROXY protocol v2` si `send_proxy_v2 = true`) usando el modo de reenvío configurado (`none`, `bungeecord` u `obsidian` firmado con `HMAC-SHA256`) y habilita compresión mediante **Set Compression (0x03)**.
5. **Clientbound Login Success (0x02):** `LoginSuccess::encode_for_version` consolida la conexión hacia el cliente adaptando el formato a su versión de protocolo (UUID en cadena con guiones en `< 735`, UUID binario sin propiedades en `735..=758`, con propiedades en `759..=765`, e incluyendo el byte booleano obligatorio `strict_error_handling = false` en `>= 766` / Minecraft 1.20.5+).
6. **Login Acknowledged (0x03)** (Versiones `>= 1.20.2`): El cliente responde confirmando el inicio de sesión y entra en la **Configuration Phase** (donde también puede ser retenido con `Keep Alive 0x04` durante el arranque bajo demanda con la estrategia `Hold`) seguida de **Play**, cuyos paquetes son puenteados bidireccionalmente entre cliente y backend.

## 5. Server List Ping (SLP) y ChatDescription JSON
Para el estado Status (`1`), gestionado en `src/status.rs`, el flujo es estricto:
- **Status Request (0x00)** sin payload.
- **Status Response (0x00)** con un String JSON (`ServerStatus`).
- Seguido de un test de latencia usando **Ping Request (0x01)** con un `i64` timestamp, que se devuelve intacto en un **Pong Response (0x01)**.

El procesamiento del JSON cuenta con el `ChatDescription` (utilizado para el Mensaje del Día o *MOTD*). Dado que los clientes más antiguos envían cadenas simples y los modernos envían JSON estructurado, `ChatDescription` se define en Rust como un `enum` con atributo `#[serde(untagged)]` para realizar un parseo polimórfico:
- `Plain(String)`
- `Structured(ChatStructured)` (con `deny_unknown_fields` para ser estricto ante un esquema de texto específico)
- `Object(serde_json::Value)` (como *fallback* para elementos extra complejos de chat).

## 6. Criptografía y Cifrado Simétrico: Fijación de AES-128-CFB8
El protocolo de Minecraft demanda el uso de cifrado **AES-128-CFB8** en modo bidireccional (`AES/CFB8/NoPadding`) empleando el `shared_secret` tanto para la llave (key) como para el Vector de Inicialización (IV).
El algoritmo del hash SHA-1 que utiliza Mojang para validar la autenticación (`compute_server_hash` en `src/crypto.rs`) genera un entero en complemento a dos, representable con un signo negativo inicial y descartando ceros a la izquierda.

**Corrección Crítica de CFB8:**
Al implementar un *stream cipher* sobre un cifrado de bloques (`cfb8::Encryptor<Aes128>`), es común incurrir en errores llamando a métodos de conveniencia como `apply_keystream`. Sin embargo, esto corrompe o restablece el IV en un entorno de red donde los paquetes varían arbitrariamente en tamaño y no se entregan alineados en memoria.
Para solventar esto y **preservar el IV correctamente**, la implementación de `crypto.rs` procesa los datos iterando byte a byte utilizando procesamiento bloque por bloque (`BlockEncryptMut`):

```rust
pub fn encrypt(&mut self, data: &mut [u8]) {
    for byte in data.iter_mut() {
        let mut block = GenericArray::from([*byte]);
        self.cipher.encrypt_block_mut(&mut block);
        *byte = block[0];
    }
}
```
Esto asegura que la matriz de inicialización se desplace exactamente un solo byte en cada iteración por la naturaleza de *Cipher Feedback de 8 bits*, logrando una sincronización de red impecable incluso a través de fragmentación TCP y evitando la repetición del keystream (confirmado bajo la suite de tests unitarios `test_no_keystream_repetition`).
