// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/naive/naive_capsule_socket.h"

#include <algorithm>
#include <cstdint>
#include <utility>

#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/memory/scoped_refptr.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/socket/stream_socket.h"
#include "net/third_party/quiche/src/quiche/common/quiche_data_writer.h"

namespace net {

namespace {

constexpr uint64_t kDatagramCapsuleType = 0;

}  // namespace

NaiveCapsuleSocket::NaiveCapsuleSocket(StreamSocket* transport_socket)
    : transport_socket_(transport_socket),
      read_buffer_(base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize)) {
  DCHECK(transport_socket_);
}

NaiveCapsuleSocket::~NaiveCapsuleSocket() {
  Disconnect();
}

void NaiveCapsuleSocket::Disconnect() {
  weak_ptr_factory_.InvalidateWeakPtrs();
  transport_socket_ = nullptr;
  read_user_buf_ = nullptr;
  read_user_buf_len_ = 0;
  read_callback_.Reset();
  read_buffer_ = nullptr;
  read_buffer_offset_ = 0;
  read_buffer_size_ = 0;
  read_payload_buf_ = nullptr;
  pending_read_ = PendingRead::kNone;
  write_user_payload_len_ = 0;
  write_callback_.Reset();
  write_buf_ = nullptr;
}

int NaiveCapsuleSocket::Read(IOBuffer* buf,
                             int buf_len,
                             CompletionOnceCallback callback) {
  DCHECK(buf);
  DCHECK(callback);
  DCHECK(!read_callback_);
  DCHECK(!read_user_buf_);
  DCHECK_EQ(pending_read_, PendingRead::kNone);

  if (!transport_socket_) {
    return ERR_SOCKET_NOT_CONNECTED;
  }
  if (buf_len <= 0) {
    return ERR_INVALID_ARGUMENT;
  }

  read_user_buf_ = base::WrapRefCounted(buf);
  read_user_buf_len_ = buf_len;
  read_callback_ = std::move(callback);

  int rv = DoReadLoop();
  if (rv != ERR_IO_PENDING) {
    read_user_buf_ = nullptr;
    read_user_buf_len_ = 0;
    read_callback_.Reset();
    read_payload_buf_ = nullptr;
    pending_read_ = PendingRead::kNone;
  }
  return rv;
}

int NaiveCapsuleSocket::Write(
    IOBuffer* buf,
    int buf_len,
    CompletionOnceCallback callback,
    const NetworkTrafficAnnotationTag& traffic_annotation) {
  DCHECK(buf);
  DCHECK(callback);
  DCHECK(!write_buf_);
  DCHECK(!write_callback_);

  if (!transport_socket_) {
    return ERR_SOCKET_NOT_CONNECTED;
  }
  if (buf_len < 0) {
    return ERR_INVALID_ARGUMENT;
  }
  if (static_cast<size_t>(buf_len) > kMaxDatagramPayloadSize) {
    return ERR_MSG_TOO_BIG;
  }

  const uint64_t capsule_payload_len = static_cast<uint64_t>(buf_len) + 1;
  const size_t header_len =
      quiche::QuicheDataWriter::GetVarInt62Len(kDatagramCapsuleType) +
      quiche::QuicheDataWriter::GetVarInt62Len(capsule_payload_len) +
      quiche::QuicheDataWriter::GetVarInt62Len(/*context_id=*/0);
  const size_t capsule_len = header_len + static_cast<size_t>(buf_len);
  auto capsule_buffer = base::MakeRefCounted<IOBufferWithSize>(capsule_len);
  quiche::QuicheDataWriter writer(header_len, capsule_buffer->data());
  if (!writer.WriteVarInt62(kDatagramCapsuleType) ||
      !writer.WriteVarInt62(capsule_payload_len) ||
      !writer.WriteVarInt62(/*context_id=*/0) ||
      writer.length() != header_len) {
    return ERR_FAILED;
  }
  capsule_buffer->span()
      .subspan(header_len, static_cast<size_t>(buf_len))
      .copy_from(buf->first(static_cast<size_t>(buf_len)));

  write_buf_ = base::MakeRefCounted<DrainableIOBuffer>(
      std::move(capsule_buffer), capsule_len);
  write_user_payload_len_ = buf_len;
  write_callback_ = std::move(callback);

  int rv = WriteDrain(traffic_annotation);
  if (rv != ERR_IO_PENDING) {
    int payload_len = write_user_payload_len_;
    write_buf_ = nullptr;
    write_user_payload_len_ = 0;
    write_callback_.Reset();
    return rv == OK ? payload_len : rv;
  }
  return rv;
}

int NaiveCapsuleSocket::DoReadLoop() {
  DCHECK(transport_socket_);

  while (true) {
    if (read_state_ == ReadState::kCapsuleType ||
        read_state_ == ReadState::kCapsuleLength ||
        read_state_ == ReadState::kContextId) {
      if (read_state_ == ReadState::kContextId &&
          capsule_payload_remaining_ == 0) {
        DLOG(WARNING) << "CONNECT-UDP datagram missing context ID";
        return ERR_INVALID_RESPONSE;
      }
      if (read_buffer_offset_ < read_buffer_size_) {
        int rv = HandleVarIntByte(
            read_buffer_->span()[static_cast<size_t>(read_buffer_offset_++)]);
        if (rv != OK) {
          return rv;
        }
        continue;
      }
      read_buffer_offset_ = 0;
      read_buffer_size_ = 0;
      pending_read_ = PendingRead::kBuffer;
      int rv = transport_socket_->Read(
          read_buffer_.get(), kReadBufferSize,
          base::BindOnce(&NaiveCapsuleSocket::OnReadComplete,
                         weak_ptr_factory_.GetWeakPtr()));
      if (rv == ERR_IO_PENDING) {
        return rv;
      }
      rv = HandleReadResult(rv);
      if (rv != OK) {
        return rv;
      }
      continue;
    }

    if (read_state_ == ReadState::kPayload) {
      DCHECK(read_payload_buf_);
      if (read_payload_buf_->BytesRemaining() == 0) {
        int rv = read_datagram_len_;
        read_payload_buf_ = nullptr;
        read_state_ = ReadState::kCapsuleType;
        read_datagram_len_ = 0;
        return rv;
      }
      if (read_buffer_offset_ < read_buffer_size_) {
        const int copy_len = std::min(read_payload_buf_->BytesRemaining(),
                                      read_buffer_size_ - read_buffer_offset_);
        read_payload_buf_->span()
            .first(static_cast<size_t>(copy_len))
            .copy_from(read_buffer_->span().subspan(
                static_cast<size_t>(read_buffer_offset_),
                static_cast<size_t>(copy_len)));
        read_buffer_offset_ += copy_len;
        read_payload_buf_->DidConsume(copy_len);
        continue;
      }
      int rv = transport_socket_->Read(
          read_payload_buf_.get(), read_payload_buf_->BytesRemaining(),
          base::BindOnce(&NaiveCapsuleSocket::OnReadComplete,
                         weak_ptr_factory_.GetWeakPtr()));
      pending_read_ = PendingRead::kPayload;
      if (rv == ERR_IO_PENDING) {
        return rv;
      }
      rv = HandleReadResult(rv);
      if (rv != OK) {
        return rv;
      }
      continue;
    }

    DCHECK_EQ(read_state_, ReadState::kSkip);
    if (capsule_payload_remaining_ == 0) {
      read_state_ = ReadState::kCapsuleType;
      continue;
    }
    if (read_buffer_offset_ < read_buffer_size_) {
      const uint64_t skip_len = std::min<uint64_t>(
          capsule_payload_remaining_, read_buffer_size_ - read_buffer_offset_);
      read_buffer_offset_ += static_cast<int>(skip_len);
      capsule_payload_remaining_ -= skip_len;
      continue;
    }
    read_buffer_offset_ = 0;
    read_buffer_size_ = 0;
    pending_read_ = PendingRead::kBuffer;
    int rv = transport_socket_->Read(
        read_buffer_.get(), kReadBufferSize,
        base::BindOnce(&NaiveCapsuleSocket::OnReadComplete,
                       weak_ptr_factory_.GetWeakPtr()));
    if (rv == ERR_IO_PENDING) {
      return rv;
    }
    rv = HandleReadResult(rv);
    if (rv != OK) {
      return rv;
    }
  }
}

int NaiveCapsuleSocket::HandleReadResult(int result) {
  PendingRead pending_read = pending_read_;
  pending_read_ = PendingRead::kNone;

  if (result == 0 || result == ERR_CONNECTION_CLOSED) {
    // A clean EOF is valid only between capsules. RFC 9297 requires a
    // truncated capsule to be treated as a malformed HTTP message.
    if (read_state_ != ReadState::kCapsuleType || varint_bytes_read_ != 0) {
      DLOG(WARNING) << "CONNECT-UDP stream ended with a truncated capsule";
      return ERR_INVALID_RESPONSE;
    }
    return ERR_CONNECTION_CLOSED;
  }
  if (result < 0) {
    return result;
  }

  if (pending_read == PendingRead::kPayload) {
    DCHECK_LE(result, read_payload_buf_->BytesRemaining());
    read_payload_buf_->DidConsume(result);
    return OK;
  }

  DCHECK_EQ(pending_read, PendingRead::kBuffer);
  DCHECK_LE(result, kReadBufferSize);
  read_buffer_offset_ = 0;
  read_buffer_size_ = result;
  return OK;
}

int NaiveCapsuleSocket::HandleVarIntByte(uint8_t byte) {
  if (varint_bytes_read_ == 0) {
    varint_bytes_needed_ = 1 << (byte >> 6);
    varint_value_ = byte & 0x3f;
  } else {
    varint_value_ = (varint_value_ << 8) | byte;
  }
  ++varint_bytes_read_;

  if (read_state_ == ReadState::kContextId) {
    if (capsule_payload_remaining_ == 0) {
      DLOG(WARNING) << "CONNECT-UDP datagram missing context ID";
      return ERR_INVALID_RESPONSE;
    }
    --capsule_payload_remaining_;
  }

  if (varint_bytes_read_ < varint_bytes_needed_) {
    return OK;
  }

  uint64_t value = varint_value_;
  varint_value_ = 0;
  varint_bytes_read_ = 0;
  varint_bytes_needed_ = 0;

  if (read_state_ == ReadState::kCapsuleType) {
    capsule_type_ = value;
    read_state_ = ReadState::kCapsuleLength;
    return OK;
  }

  if (read_state_ == ReadState::kCapsuleLength) {
    capsule_payload_remaining_ = value;
    if (capsule_type_ != kDatagramCapsuleType) {
      DVLOG(1) << "Ignoring non-DATAGRAM capsule type " << capsule_type_;
      read_state_ = ReadState::kSkip;
      return OK;
    }
    read_state_ = ReadState::kContextId;
    return OK;
  }

  DCHECK_EQ(read_state_, ReadState::kContextId);
  if (value != 0) {
    DVLOG(1) << "Ignoring CONNECT-UDP datagram for unsupported context ID "
             << value;
    read_state_ = ReadState::kSkip;
    return OK;
  }
  if (capsule_payload_remaining_ > kMaxDatagramPayloadSize) {
    // RFC 9298 requires context-zero payloads larger than a UDP payload to
    // abort the corresponding stream.
    DLOG(WARNING) << "Rejecting oversized CONNECT-UDP datagram: "
                  << capsule_payload_remaining_;
    return ERR_INVALID_RESPONSE;
  }
  if (capsule_payload_remaining_ > static_cast<uint64_t>(read_user_buf_len_)) {
    DLOG(WARNING) << "CONNECT-UDP datagram too large for read buffer: "
                  << capsule_payload_remaining_ << " > " << read_user_buf_len_;
    read_state_ = ReadState::kSkip;
    return ERR_MSG_TOO_BIG;
  }

  read_datagram_len_ = static_cast<int>(capsule_payload_remaining_);
  read_payload_buf_ = base::MakeRefCounted<DrainableIOBuffer>(
      read_user_buf_, read_datagram_len_);
  capsule_payload_remaining_ = 0;
  read_state_ = ReadState::kPayload;
  return OK;
}

void NaiveCapsuleSocket::OnReadComplete(int result) {
  DCHECK_NE(result, ERR_IO_PENDING);
  DCHECK(read_callback_);
  DCHECK(read_user_buf_);

  int rv = HandleReadResult(result);
  if (rv == OK) {
    rv = DoReadLoop();
  }
  if (rv == ERR_IO_PENDING) {
    return;
  }

  read_user_buf_ = nullptr;
  read_user_buf_len_ = 0;
  CompletionOnceCallback callback = std::move(read_callback_);
  read_payload_buf_ = nullptr;
  pending_read_ = PendingRead::kNone;
  std::move(callback).Run(rv);
}

int NaiveCapsuleSocket::WriteDrain(
    const NetworkTrafficAnnotationTag& traffic_annotation) {
  DCHECK(transport_socket_);
  DCHECK(write_buf_);

  while (write_buf_->BytesRemaining() > 0) {
    int rv = transport_socket_->Write(
        write_buf_.get(), write_buf_->BytesRemaining(),
        base::BindOnce(&NaiveCapsuleSocket::OnWriteComplete,
                       weak_ptr_factory_.GetWeakPtr(), traffic_annotation),
        traffic_annotation);
    if (rv == ERR_IO_PENDING) {
      return rv;
    }
    if (rv < 0) {
      return rv;
    }
    if (rv == 0) {
      return ERR_CONNECTION_CLOSED;
    }
    write_buf_->DidConsume(rv);
  }

  return OK;
}

void NaiveCapsuleSocket::OnWriteComplete(
    const NetworkTrafficAnnotationTag& traffic_annotation,
    int result) {
  DCHECK_NE(result, ERR_IO_PENDING);
  DCHECK(write_callback_);
  DCHECK(write_buf_);

  if (result > 0) {
    write_buf_->DidConsume(result);
    result = WriteDrain(traffic_annotation);
  } else if (result == 0) {
    result = ERR_CONNECTION_CLOSED;
  }

  if (result == ERR_IO_PENDING) {
    return;
  }

  int payload_len = write_user_payload_len_;
  write_buf_ = nullptr;
  write_user_payload_len_ = 0;
  std::move(write_callback_).Run(result == OK ? payload_len : result);
}

}  // namespace net
