/*
 * net.h
 *
 * Blocking socket helpers that handle short reads and short writes.
 * TCP is a byte stream: send() can write fewer bytes than asked and recv()
 * can read fewer bytes than asked. Every framed read/write in this project
 * goes through these two functions instead of raw send/recv.
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
