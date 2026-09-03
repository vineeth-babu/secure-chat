/*
 * net.h -- CS6008 Phase 2
 *
 * Blocking socket helpers that deal with short reads and short writes.
 * TCP is a byte stream: a single send() may transmit fewer bytes than asked,
 * and a single recv() may return fewer bytes than asked. Every framed read or
 * write in this project goes through these two functions.
 */

#ifndef NET_H
#define NET_H

#include <cstddef>

namespace net {

/* Read exactly n bytes into buf. Returns false on EOF or error. */
bool read_exact(int fd, void *buf, size_t n);

/* Write exactly n bytes from buf. Returns false on error. */
bool write_all(int fd, const void *buf, size_t n);

}  /* namespace net */

#endif /* NET_H */
