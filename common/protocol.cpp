#include "common/protocol.h"

namespace fwds {

bool closesConnection(int code) {
  if (code == static_cast<int>(ErrorCode::BadJson)) return false;
  return code >= 1000 && code < 3000;
}

const char* msgTypeName(quint8 type) {
  switch (static_cast<MsgType>(type)) {
    case MsgType::Login: return "LOGIN";
    case MsgType::LoginResult: return "LOGIN_RESULT";
    case MsgType::Heartbeat: return "HEARTBEAT";
    case MsgType::HeartbeatAck: return "HEARTBEAT_ACK";
    case MsgType::UpdateNotify: return "UPDATE_NOTIFY";
    case MsgType::UpdateCancel: return "UPDATE_CANCEL";
    case MsgType::ChunkReq: return "CHUNK_REQ";
    case MsgType::ChunkData: return "CHUNK_DATA";
    case MsgType::Progress: return "PROGRESS";
    case MsgType::Result: return "RESULT";
    case MsgType::Alert: return "ALERT";
    case MsgType::Bye: return "BYE";
    case MsgType::Error: return "ERROR";
  }
  return "UNKNOWN";
}

const char* errorName(ErrorCode code) {
  switch (code) {
    case ErrorCode::Ok: return "OK";
    case ErrorCode::BadMagic: return "BAD_MAGIC";
    case ErrorCode::BadVersion: return "BAD_VERSION";
    case ErrorCode::FrameTooLarge: return "FRAME_TOO_LARGE";
    case ErrorCode::UnexpectedMessage: return "UNEXPECTED_MESSAGE";
    case ErrorCode::BadJson: return "BAD_JSON";
    case ErrorCode::SeqError: return "SEQ_ERROR";
    case ErrorCode::LoginTimeout: return "LOGIN_TIMEOUT";
    case ErrorCode::TsOutOfWindow: return "TS_OUT_OF_WINDOW";
    case ErrorCode::IdCertMismatch: return "ID_CERT_MISMATCH";
    case ErrorCode::DeviceAuthFailed: return "DEVICE_AUTH_FAILED";
    case ErrorCode::LicenseInvalid: return "LICENSE_INVALID";
    case ErrorCode::DeviceLocked: return "DEVICE_LOCKED";
    case ErrorCode::TooManyConnections: return "TOO_MANY_CONNECTIONS";
    case ErrorCode::SigInvalid: return "SIG_INVALID";
    case ErrorCode::ModelMismatch: return "MODEL_MISMATCH";
    case ErrorCode::RollbackAttempt: return "ROLLBACK_ATTEMPT";
    case ErrorCode::ChunkTampered: return "CHUNK_TAMPERED";
    case ErrorCode::ImageTampered: return "IMAGE_TAMPERED";
    case ErrorCode::WriteFailed: return "WRITE_FAILED";
    case ErrorCode::SelftestFailed: return "SELFTEST_FAILED";
    case ErrorCode::BootFailed: return "BOOT_FAILED";
    case ErrorCode::PkgNotFound: return "PKG_NOT_FOUND";
    case ErrorCode::ChunkOutOfRange: return "CHUNK_OUT_OF_RANGE";
    case ErrorCode::DiskFull: return "DISK_FULL";
    case ErrorCode::Cancelled: return "CANCELLED";
    case ErrorCode::Busy: return "BUSY";
  }
  return "UNKNOWN";
}

}  // namespace fwds
