# Implementación del Protocolo Bedrock en Obsidian

El protocolo de Minecraft Bedrock Edition viaja como contenido útil (payload) dentro de los datagramas RakNet. El crate `obsidian-bedrock` se encarga de procesar los lotes (batches) de compresión y del fraccionamiento en paquetes individuales.

## 1. Batching y Compresión
La recepción principal y extracción de los datos Bedrock sucede en `batch.rs`. Un "Batch Packet" se identifica estrictamente porque comienza con el header byte `0xFE`.
Bedrock admite varios modos de compresión gestionados mediante el enum `CompressionMode`:
*   **None**: Se utiliza el bloque de `Bytes` sin alteraciones.
*   **Zlib**: Se usa `flate2::read::ZlibDecoder` con un límite estricto de lectura (`Read::take(MAX_BATCH_DECOMPRESSED_LEN + 1)`, donde `MAX_BATCH_DECOMPRESSED_LEN = 4 MiB`) para rechazar bombas de compresión devolviendo `BatchError::DecompressedBatchTooLarge` en lugar de truncar silenciosamente paquetes válidos.
*   **Snappy**: Se emplea el crate `snap` validando la longitud descomprimida esperada (`decompress_len <= MAX_BATCH_DECOMPRESSED_LEN`) antes de reservar memoria.

## 2. Decodificación de VarInts
Tras la descompresión de un batch, el payload contiene múltiples paquetes Bedrock concatenados, cada uno precedido por su longitud codificada como un número entero de longitud variable (*VarInt*).
En `codec.rs`, la función `read_varint` implementa la extracción segura del VarInt de 32 bits no firmado (`u32`):
*   Se lee byte a byte validando el bit más significativo (`0x80`).
*   **Protección contra bucles infinitos**: Si el desplazamiento (`shift`) alcanza o supera los 35 bits, arroja inmediatamente un `DecodeError::InvalidVarInt` para evitar un ataque de denegación de servicio a través de VarInts alterados maliciosamente.

## 3. Extracción de Paquetes (Framing)
La función `extract_packets` subdivide el buffer unificado del batch utilizando segmentaciones zero-copy cortesía del crate `bytes`.
Avanzando recursivamente en la memoria:
1. Lee la longitud (VarInt).
2. Valida la disponibilidad de memoria: `if uncompressed_payload.remaining() < len { return Err(DecodeError::TooShort); }`
3. Fragmenta la memoria usando `.split_to(len)`.
4. Devuelve un vector de frames (`Vec<Bytes>`), cada uno correspondiendo a un datagrama decodificable e individual del protocolo de aplicación (Game packets).
