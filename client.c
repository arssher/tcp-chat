#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <unistd.h>

#define MAXEVENTS 64
#define DEFAULT_PORT_TO_CONNECT_TO "3010"
#define MAX_MESSAGE_LENGTH 1025

static int create_and_connect(const char *port)
{
    struct addrinfo hints;
    struct addrinfo *result;
    int s;
    int sfd = -1;

    memset(&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = AF_INET;  // we want IPv4 socket
    hints.ai_socktype = SOCK_STREAM; // We want a TCP socket
    hints.ai_flags = 0;

    s = getaddrinfo("127.0.0.1", port, &hints, &result);
    if (s != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        return -1;
    }

    struct addrinfo *ai;
    for (ai = result; ai != NULL; ai = ai->ai_next)
    {
        printf("Received suitable socket, checking it...\n");
        sfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sfd == -1)
            continue;

        s = connect(sfd, ai->ai_addr, ai->ai_addrlen);
        if (s == 0)
        {
            printf("Successful connect!\n");
            break;
        }

        close(sfd);
    }

    freeaddrinfo(result);
    return sfd;
}

// set O_NONBLOCK flag on a given socket, making it non-blocking
// returns -1 in case of failure, 0 if ok
static int make_socket_non_blocking(int sfd)
{
    int flags, s;

    flags = fcntl(sfd, F_GETFL); // get current flags
    if (flags == -1)
    {
        perror("fcntl failed while getting flags");
        return -1;
    }

    flags |= O_NONBLOCK;
    s = fcntl(sfd, F_SETFL, flags); // set updated flags with O_NONBLOCK
    if (s == -1)
    {
        perror ("fcntl failed while setting flags");
        return -1;
    }

    return 0;
}

int main() {
    int socket_fd = create_and_connect(DEFAULT_PORT_TO_CONNECT_TO);
    if (socket_fd == -1)
    {
        exit(1);
    }

    if (make_socket_non_blocking(socket_fd) == -1)
    {
        fprintf(stderr, "failed to make socket nonblocking");
        exit(1);
    }

    if (make_socket_non_blocking(1) == -1)
    {
        fprintf(stderr, "failed to make stdin nonblocking");
        exit(1);
    }

    while (1948) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(1, &readfds); // add stdin to select
        FD_SET(socket_fd, &readfds); // add stdin to select

        int select_res = select(socket_fd + 1, &readfds, NULL, NULL, NULL);
        if (select_res < 1)
        {
            fprintf(stderr, "select failed\n");
            continue;
        }

        if (FD_ISSET(1, &readfds))
        {
            printf("user typed something, transmitting to server\n");
        }

        if (FD_ISSET(socket_fd, &readfds))
        {
            printf("Something came from the server\n");
        }
    }


    return 0;
}