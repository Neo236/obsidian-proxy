pub mod auth;
pub mod compression;
pub mod crypto;
pub mod frame;
pub mod handshake;
pub mod login;
pub mod status;
pub mod varint;

pub use auth::{
    authenticate_user, authenticate_user_with_client, AuthError, GameProfile, ProfileProperty,
};
pub use compression::{
    compress_zlib, decompress_zlib, CompressionError, PacketCompressor, PacketDecompressor,
};
pub use crypto::{
    compute_server_hash, decrypt_rsa, generate_rsa_keypair, minecraft_sha1_hex,
    public_key_der, Aes128Cfb8Cipher, Aes128Cfb8Decryptor, Aes128Cfb8Encryptor, CryptoError,
};
pub use frame::{
    decode_frame, decode_frame_limited, encode_frame, FrameError, PacketFrame, PacketReader,
    PacketStream, PacketWriter, MAX_PACKET_SIZE,
};
pub use handshake::{
    parse_server_address, Handshake, HandshakeError, Modloader, NextState, HANDSHAKE_PACKET_ID,
};
pub use login::{
    EncryptionRequest, EncryptionResponse, LoginClientbound, LoginDisconnect, LoginError,
    LoginServerbound, LoginStart, LoginSuccess, Property, SetCompression,
    ENCRYPTION_REQUEST_PACKET_ID, ENCRYPTION_RESPONSE_PACKET_ID, LOGIN_DISCONNECT_PACKET_ID,
    LOGIN_START_PACKET_ID, LOGIN_SUCCESS_PACKET_ID, SET_COMPRESSION_PACKET_ID,
};
pub use status::{
    ChatDescription, PlayerSample, PlayersInfo, PingRequest, PongResponse, ServerStatus,
    StatusClientbound, StatusError, StatusRequest, StatusResponse, StatusServerbound,
    VersionInfo, PING_PACKET_ID, PONG_PACKET_ID, STATUS_REQUEST_PACKET_ID,
    STATUS_RESPONSE_PACKET_ID,
};
pub use varint::{
    decode_varint_slice, decode_varlong_slice, read_string, read_varint, read_varlong,
    string_size, varint_size, varlong_size, write_string, write_varint, write_varlong,
    VarIntBufExt, VarIntBufMutExt, VarIntError,
};
