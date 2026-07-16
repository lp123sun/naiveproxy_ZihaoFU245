// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_NAIVE_NAIVE_CAPSULE_SOCKET_H_
#define NET_TOOLS_NAIVE_NAIVE_CAPSULE_SOCKET_H_

#include <cstddef>
#include <cstdint>

#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "net/base/completion_once_callback.h"
#include "net/base/io_buffer.h"
#include "net/traffic_annotation/network_traffic_annotation.h"

namespace net {

class StreamSocket;

class NaiveCapsuleSocket {
 public:
  explicit NaiveCapsuleSocket(StreamSocket* transport_socket);

  NaiveCapsuleSocket(const NaiveCapsuleSocket&) = delete;
  NaiveCapsuleSocket& operator=(const NaiveCapsuleSocket&) = delete;

  ~NaiveCapsuleSocket();

  void Disconnect();

  // Returns the datagram payload size. Empty datagrams return zero; transport
  // EOF is reported as ERR_CONNECTION_CLOSED.
  int Read(IOBuffer* buf, int buf_len, CompletionOnceCallback callback);

  int Write(IOBuffer* buf,
            int buf_len,
            CompletionOnceCallback callback,
            const NetworkTrafficAnnotationTag& traffic_annotation);

 private:
  static constexpr size_t kMaxDatagramPayloadSize = 65527;
  static constexpr int kReadBufferSize = 4096;

  enum class ReadState {
    kCapsuleType,
    kCapsuleLength,
    kContextId,
    kPayload,
    kSkip,
  };

  enum class PendingRead {
    kNone,
    kBuffer,
    kPayload,
  };

  int DoReadLoop();
  int HandleReadResult(int result);
  int HandleVarIntByte(uint8_t byte);
  void OnReadComplete(int result);

  int WriteDrain(const NetworkTrafficAnnotationTag& traffic_annotation);
  void OnWriteComplete(const NetworkTrafficAnnotationTag& traffic_annotation,
                       int result);

  // Non-owning. The pooled stream remains owned by ClientSocketHandle.
  StreamSocket* transport_socket_;

  scoped_refptr<IOBuffer> read_user_buf_;
  int read_user_buf_len_ = 0;
  CompletionOnceCallback read_callback_;
  scoped_refptr<IOBufferWithSize> read_buffer_;
  int read_buffer_offset_ = 0;
  int read_buffer_size_ = 0;
  scoped_refptr<DrainableIOBuffer> read_payload_buf_;
  ReadState read_state_ = ReadState::kCapsuleType;
  PendingRead pending_read_ = PendingRead::kNone;
  uint64_t capsule_type_ = 0;
  uint64_t capsule_payload_remaining_ = 0;
  uint64_t varint_value_ = 0;
  int varint_bytes_read_ = 0;
  int varint_bytes_needed_ = 0;
  int read_datagram_len_ = 0;

  int write_user_payload_len_ = 0;
  CompletionOnceCallback write_callback_;
  scoped_refptr<DrainableIOBuffer> write_buf_;

  base::WeakPtrFactory<NaiveCapsuleSocket> weak_ptr_factory_{this};
};

}  // namespace net

#endif  // NET_TOOLS_NAIVE_NAIVE_CAPSULE_SOCKET_H_
