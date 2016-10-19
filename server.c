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

typedef struct socket_with_msg {
    struct socket_with_msg *next;
    int socket_fd;
    char buff[MAX_MESSAGE_LENGTH * 2]; // to be able to concat string without additional fuss
    size_t buff_size; // current buff size, not null-terminated!
} socket_with_msg;

static void add_socket(socket_with_msg **root, int socket_fd)
{
    socket_with_msg *new_node;
    new_node = (socket_with_msg*)malloc(sizeof(socket_with_msg));
    new_node->socket_fd = socket_fd;
    new_node->buff_size = 0;
    new_node->next = *root;
    *root = new_node;
}

static void remove_socket(socket_with_msg **root, int socket_fd)
{
    // no elements
    if (*root == NULL)
    {
        printf("an attempt to remove from empty list\n");
    }

    socket_with_msg *previous = *root;
    socket_with_msg *next = previous->next;

    // first element needs to be removed
    if (previous->socket_fd == socket_fd)
    {
        free(previous);
        *root = next;
        printf("socked removed from list\n");
        return;
    }

    // ok, it is in the middle
    while (next)
    {
        if (next->socket_fd == socket_fd)
        {
            previous->next = next->next;
            free(next);
            printf("socked removed form list\n");
            return;
        }
        previous = next;
        next = next->next;
    }
    printf("socket for removing not found\n");
}

static socket_with_msg* find_socket(socket_with_msg *root, int fd) {
    socket_with_msg *current = root;
    while (current)
    {
        if (current->socket_fd == fd)
            return current;
        current = current->next;
    }
    printf("socket not found, returning null");
    return NULL;
}

static int socket_add_to_buf(socket_with_msg *sock_m, char *buf, size_t size)
{
    if (size + sock_m->buff_size > 2 * MAX_MESSAGE_LENGTH)
    {
        fprintf(stderr, "Attempt to add too big buffer");
        return -1;
    }
    memcpy(sock_m->buff + sock_m->buff_size, buf, size);
    sock_m->buff_size += size;
    return 0;
}

static void print_sockets(socket_with_msg *root)
{
    socket_with_msg *current = root;
    while (current) {
        printf("Socket %d, msg size %d; ", current->socket_fd, (int)current->buff_size);
        current = current->next;
    }
    printf("\n");
}

static void accept_new_connections(int epoll_fd, int listening_socket_fd, socket_with_msg **sockets_with_msg) {
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

        int err;
        if ((err = getnameinfo(&in_addr, in_len,
                        hbuf, sizeof(hbuf), // hostname will be put there
                        sbuf, sizeof(sbuf), // service address will be put there
                        NI_NUMERICHOST | NI_NUMERICSERV)) // don't resolve hostname and service address
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
        add_socket(sockets_with_msg, incoming_fd);
        printf("______________printing all incoming sockets____________________\n");
        print_sockets(*sockets_with_msg);
    }
}

static void send_message(int fd, char *msg, size_t msg_size, socket_with_msg *sockets_with_msg)
{
    printf("Message from fd %d:\n", fd);
    if (write(1, msg, msg_size) == -1)
    {
        perror("error while writing to stdout");
    }
    printf("now let's send it to all the clients\n");
    // TODO: rewrite in non-blocking regime
    socket_with_msg *current = sockets_with_msg;
    while (current)
    {
        size_t bytes_sent = 0;
        char *msg_start = msg;
        size_t msg_size_left = msg_size;
        while (bytes_sent != msg_size)
        {
            ssize_t count = write(current->socket_fd, msg_start, msg_size_left);
            if (count == -1)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    fprintf(stderr, "buffer is busy, trying again\n");
                    continue;
                }
                else
                {
                    fprintf(stderr, "something nasty happened while writing to client, ignoring it\n");
                    break;
                }
            }
            else
            {
                bytes_sent += count;
                msg_start += count;
                msg_size_left -= count;
            }

        }
        printf("if you don't see errors above, message was sent successfully\n");
        current = current->next;
    }
}

// send every '\n' terminating string found in sock_m's buffer
static void send_messages_from_socket(socket_with_msg *sock_m, socket_with_msg *sockets_with_msg)
{
    char *msg_start = sock_m->buff;
    size_t msg_size = 0;
    size_t full_buff_size = sock_m->buff_size;

    for (size_t i = 0; i < full_buff_size; i++)
    {
        if (msg_start[msg_size] == '\n')
        {
            // found message
            send_message(sock_m->socket_fd, msg_start, msg_size + 1, sockets_with_msg);
            memmove(sock_m->buff, sock_m->buff + msg_size + 1, sock_m->buff_size - msg_size - 1);
            sock_m->buff_size -= msg_size + 1;
            msg_start = sock_m->buff;
            msg_size =  0;
        }
        else
            msg_size++;
    }

    // TODO: add check if more than MAX_MESSAGE bytes left and reset sock_m if that the case
}

static void receive_data(int fd_to_read, socket_with_msg **sockets_with_msg)
{
    int close_connection = 0; // true, if this connection is closed
    socket_with_msg *sock_m = find_socket(*sockets_with_msg, fd_to_read);

    while (1948)
    {
        char buf[MAX_MESSAGE_LENGTH]; // put message on this iteration here
        ssize_t count; // bytes read on this iteration

        // -1 because of \0
        count = read(fd_to_read, buf, sizeof(buf) - 1);
        if (count == -1)
        {
            if (errno == EAGAIN)
            {
                printf("All the data is read for now, returning to epoll_wait");
            }
            else
            {
                perror("error while reading, closing connection");
                close_connection = 1;
            }
            break;
        }
        else if (count == 0)
        {
            printf("EOF on fd %d, closing connection\n", fd_to_read);
            close_connection = 1;
            break;
        }
        else
        {
            // data arrived, add it to our buffer and send messages
            socket_add_to_buf(sock_m, buf, count);
            send_messages_from_socket(sock_m, *sockets_with_msg);
        }
    }

    if (close_connection)
    {
        // send rest of the data, if anything left
        if (sock_m->buff_size != 0)
        {
            send_message(sock_m->socket_fd, sock_m->buff, sock_m->buff_size, *sockets_with_msg);
        }
        // now close the socket
        remove_socket(sockets_with_msg, fd_to_read);
        close(fd_to_read);
        printf("Closed connection on descriptor %d\n", fd_to_read);
    }
}

static void event_loop(int epoll_fd, int listening_socket_fd)
{
    // buffer where events are returned from epoll
    struct epoll_event *events = (struct epoll_event*)calloc(MAXEVENTS, sizeof(struct epoll_event));
    socket_with_msg *sockets_with_msg = NULL; // socket fds with accumulated msgs
    int end_of_world = 0;
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
                accept_new_connections(epoll_fd, listening_socket_fd, &sockets_with_msg);
            }

            else
            {
                int fd_to_read = events[i].data.fd;
                printf("Receiving data from descriptor %d\n", fd_to_read);
                receive_data(fd_to_read, &sockets_with_msg);
            }
        }
        if (end_of_world) // just to suppress infinite loop warning
            break;
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