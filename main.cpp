#include <iostream>

int main() {
    std::cout << "Hello, World!" << std::endl;
    return 0;
}

// send & receive on epolled socket -- how -- better in non-blocking regime with a buffer

// why not epoll for client -- no need, but possible? -- yes
// select on stdin for client, right -- yes
// should we do shutdown before close -- doesn't matter without multiprocessing
// why getaddrinfo? in general for dns resolving, but what I do is also possible
// yes, reads may be arbitrary fragmented
// why edge triggered mode requires nonblocking socket? because otherwise we
// will hang on the last read -- we have to read everything.

// client is expected not to insert \0 in his messages!
// todo: check buf[MACRO*2]
