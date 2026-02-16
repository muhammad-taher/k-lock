#include "include/common.h"
#include <arpa/inet.h>

using namespace std;

unsigned int ip_to_int(const string& ip) {
    struct sockaddr_in sa;
    inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr));
    return sa.sin_addr.s_addr;
}
