/*
 * net.cpp
 */

#include "net.h"

#include <sys/socket.h>
#include <cerrno>

namespace net {

bool read_exact(int fd, void *buf, size_t n)
{
    unsigned char *p = static_cast<unsigned char *>(buf);

    while (n > 0) {
        ssize_t r = recv(fd, p, n, 0);

        if (r == 0)
            return false;                   /* peer closed the connection */

        if (r < 0) {
            if (errno == EINTR)
                continue;                   /* interrupted, retry         */
            return false;
        }

        p += r;
        n -= static_cast<size_t>(r);
    }

    return true;
}

bool write_all(int fd, const void *buf, size_t n)
{
    const unsigned char *p = static_cast<const unsigned char *>(buf);

    while (n > 0) {
        /* MSG_NOSIGNAL: a write to a closed socket returns EPIPE instead of
           killing the process with SIGPIPE. */
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);

        if (w <= 0) {
            if (w < 0 && errno == EINTR)
                continue;
            return false;
        }

        p += w;
        n -= static_cast<size_t>(w);
    }

    return true;
}

}  /* namespace net */
