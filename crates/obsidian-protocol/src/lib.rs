pub mod auth;
pub mod compression;
pub mod crypto;
pub mod frame;
pub mod handshake;
pub mod login;
pub mod proxy_protocol;
pub mod status;
pub mod varint;

pub use auth::{
    AuthClient, AuthError, GameProfile, ProfileProperty, authenticate_user,
    authenticate_user_with_client,
};
pub use compression::{
    CompressionError, PacketCompressor, PacketDecompressor, compress_zlib, decompress_zlib,
};
pub use crypto::{
    Aes128Cfb8Cipher, Aes128Cfb8Decryptor, Aes128Cfb8Encryptor, CryptoError, compute_server_hash,
    decrypt_rsa, generate_rsa_keypair, minecraft_sha1_hex, public_key_der,
};
pub use frame::{
    FrameError, MAX_PACKET_SIZE, PacketFrame, PacketReader, PacketStream, PacketWriter,
    decode_frame, decode_frame_limited, encode_frame,
};
pub use handshake::{
    HANDSHAKE_PACKET_ID, Handshake, HandshakeError, Modloader, NextState, OBSIDIAN_FORWARDING_TAG,
    VerifiedObsidianForwarding, parse_server_address,
};
pub use login::{
    ENCRYPTION_REQUEST_PACKET_ID, ENCRYPTION_RESPONSE_PACKET_ID, EncryptionRequest,
    EncryptionResponse, LOGIN_DISCONNECT_PACKET_ID, LOGIN_START_PACKET_ID, LOGIN_SUCCESS_PACKET_ID,
    LoginClientbound, LoginDisconnect, LoginError, LoginServerbound, LoginStart, LoginSuccess,
    PROTOCOL_1_19, PROTOCOL_1_19_1, PROTOCOL_1_19_3, PROTOCOL_1_20_2, PROTOCOL_1_20_5,
    PROTOCOL_1_21_2, Property, SET_COMPRESSION_PACKET_ID, SetCompression,
};
pub use proxy_protocol::{
    MAX_PROXY_V1_LEN, MAX_PROXY_V2_LEN, PROXY_V1_PREFIX, PROXY_V2_MAGIC, ProxyHeader,
    ProxyProtocolError, encode_proxy_v2, encode_proxy_v2_local, parse_proxy_header,
    starts_with_proxy_signature,
};
pub use status::{
    ChatDescription, PING_PACKET_ID, PONG_PACKET_ID, PingRequest, PlayerSample, PlayersInfo,
    PongResponse, STATUS_REQUEST_PACKET_ID, STATUS_RESPONSE_PACKET_ID, ServerStatus,
    StatusClientbound, StatusError, StatusRequest, StatusResponse, StatusServerbound, VersionInfo,
};
pub use varint::{
    VarIntBufExt, VarIntBufMutExt, VarIntError, decode_varint_slice, decode_varlong_slice,
    read_string, read_varint, read_varlong, string_size, varint_size, varlong_size, write_string,
    write_varint, write_varlong,
};
