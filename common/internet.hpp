#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
 
#include <string>
#include <sstream>
#include <vector>
#include <iostream>
#include <buffer.hpp>
 
std::vector<std::string> dns_lookup(const std::string &host_name, int ipv=4); //ipv: default=4
bool is_ipv6_address(const std::string& str);
bool is_ipv4_address(const std::string& str);
int socket_connect(std::string ip_address, int port);
int http_get(const std::string& request, const std::string& ip_address, int port, buffer& buf);
void download(const std::string& url, buffer& buf);
 
 
