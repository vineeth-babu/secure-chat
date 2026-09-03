#ifndef NET_H
#define NET_H

#include <cstddef>

namespace net {

// Reads exactly n bytes. Returns false if the connection closes or an error occurs.
bool read_exact(int fd, void *buf, size_t n);

// Writes exactly n bytes. Returns false if an error occurs.
bool write_all(int fd, const void *buf, size_t n);

}  // namespace net

#endif