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
#define DEFAULT_PORT_TO_LISTEN_ON "3010"
#define MAX_MESSAGE_LENGTH 1025

// create socket capable of accepting connections on any of host's addresses and bind it to specified port
// returns socket fd, or -1 in case of failure
static int create_and_bind(const char *port)
{
    struct addrinfo hints;
    struct addrinfo *result;
    int s, sfd;

    memset(&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = AF_INET;  // we want IPv4 socket
    hints.ai_socktype = SOCK_STREAM; // We want a TCP socket
    hints.ai_flags = AI_PASSIVE; // we want socket capable of accept connections on any host's network addresses

    s = getaddrinfo(NULL, port, &hints, &result);
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

        s = bind(sfd, ai->ai_addr, ai->ai_addrlen);
        if (s == 0)
        {
            printf("Successful bind\n");
            char hostname[NI_MAXHOST];
            char servname[NI_MAXSERV];
            s = getnameinfo(ai->ai_addr, sizeof(ai), hostname, sizeof(hostname), servname, sizeof(servname), 0);
            if (s == 0)
            {
                printf("bind to, host=%s, serv=%s\n", hostname, servname);
            }
            else
            {
                fprintf(stderr, "getnameinfo: %s\n", gai_strerror(s));
            }
            break;
        }

        close(sfd);
    }

    if (ai == NULL)
    {
        fprintf(stderr, "Could not bind\n");
        return -1;
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

static void accept_new_connections(int epoll_fd, int listening_socket_fd) {
    while (1948) {
        struct sockaddr in_addr; // where to put incoming connection endpoint
        socklen_t in_len = sizeof(in_addr); // it's length
        int incoming_fd;
        char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
        struct epoll_event event; // here we will put our new incoming connection socket and say epoll to watch after it

        incoming_fd = accept(listening_socket_fd, &in_addr, &in_len);
        if (incoming_fd == -1)
        {
            if ((errno == EAGAIN) ||
                (errno == EWOULDBLOCK)) // no more connections available
            {
                break;
            }
            else
            {
                perror("Error while accepting");
                break;
            }
        }


        if (int err = getnameinfo(&in_addr, in_len,
                        hbuf, sizeof(hbuf), // hostname will be put there
                        sbuf, sizeof(sbuf), // service address will be put there
                        NI_NUMERICHOST | NI_NUMERICSERV) // don't resolve hostname and service address
            == 0)
        {
            printf("Accepted connection on descriptor %d "
                           "(host=%s, port=%s)\n", incoming_fd, hbuf, sbuf);
        }
        else
        {
            fprintf(stderr, "Connection was accepted, but getnameinfo failed: %s\n", gai_strerror(err));
        }

        if (make_socket_non_blocking(incoming_fd) == -1)
        {
            fprintf(stderr, "failed to make new incoming connection socket non-blocking\n");
            break;
        }

        event.data.fd = incoming_fd;
        event.events = EPOLLIN | EPOLLET;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, incoming_fd, &event) == -1)
        {
            perror("epoll_ctl while adding incoming connection");
            break;
        }
    }
}

static void receive_data(int fd_to_read)
{
    int close_connection = 0; // true, if this connection is closed
    ssize_t count; // bytes read
    char buf[MAX_MESSAGE_LENGTH];

    count = read(fd_to_read, buf, sizeof(buf));
    if (count == -1)
    {
        if (errno == EAGAIN)
        {
            printf("Suddenly all the data is read");
            return;
        }
        else
        {
            perror("error while reading, closing connections");
            close_connection = 1;
        }
    }
    else if (count == 0)
    {
        printf("EOF on fd %d, closing connection\n", fd_to_read);
        close_connection = 1;
    }
    else
    {
        printf("TODO: send the message, for now printing it\n");
        printf("Message from fd %d:\n", fd_to_read);
        if (write(1, buf, count) == -1)
        {
            perror("error while writing to stdout");
        }
    }

    // check for EOF
    if ((recv(fd_to_read, buf, sizeof(buf), MSG_PEEK | MSG_DONTWAIT)) == 0) {
        close_connection = 1;
    }

    if (close_connection)
    {
        printf("Closed connection on descriptor %d\n", fd_to_read);
        close(fd_to_read);
    }
}

static void event_loop(int epoll_fd, int listening_socket_fd)
{
    // buffer where events are returned from epoll
    struct epoll_event *events = (epoll_event*)calloc(MAXEVENTS, sizeof(struct epoll_event));
    while (1948)
    {
        // block until at least one event arrive
        int number_of_descriptors_ready = epoll_wait(epoll_fd, events, MAXEVENTS, -1);
        // iterate over events
        for (int i = 0; i < number_of_descriptors_ready; i++)
        {
            if ((events[i].events & EPOLLERR) || // error occurred on that socket
                (events[i].events & EPOLLHUP) || // hang up occured on that socket
                (!(events[i].events & EPOLLIN))) // socket not ready for read
            {
                fprintf (stderr, "An error occurred on the socket or it is not ready for reading\n");
                close(events[i].data.fd);
                continue;
            }

            else if (listening_socket_fd == events[i].data.fd)
            {
                printf("Notification on listening socket; starting accepting connections\n");
                accept_new_connections(epoll_fd, listening_socket_fd);
            }

            else
            {
                int fd_to_read = events[i].data.fd;
                printf("Receiving data from descriptor %d\n", fd_to_read);
                receive_data(fd_to_read);
            }
        }
    }
}


int main(int argc, char *argv[]) {
    int socket_fd;
    int epoll_fd;
    struct epoll_event event; // here we will put our socket_fd and say epoll to watch after it

    socket_fd = create_and_bind(DEFAULT_PORT_TO_LISTEN_ON);
    if (socket_fd == -1)
        exit(1);

    if (make_socket_non_blocking(socket_fd) == -1)
        exit(1);

    if (listen(socket_fd, SOMAXCONN) == -1)
    {
        perror ("listen");
        exit(1);
    }
    printf("Listening on port %s\n", DEFAULT_PORT_TO_LISTEN_ON);

    epoll_fd = epoll_create1(0);  // argument doesn't matter
    if (epoll_fd == -1)
    {
        perror("epoll create");
        exit(1);
    }
    printf("epoll file descriptor opened\n");

    event.data.fd = socket_fd;
    event.events = EPOLLIN | EPOLLET; // available for read | use edge triggered behaviour
    // in edge triggered mode, we will be notified only when new changes will occur on the descriptor
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socket_fd, &event) == -1) {
        perror("epoll_ctl failed while registering listening socket");
        exit(1);
    }
    printf("Listening socket registered in epoll\n");

    event_loop(epoll_fd, socket_fd);

    return 0;
}