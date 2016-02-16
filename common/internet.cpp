#include <internet.hpp>
#include <logger.hpp>

std::vector<std::string> dns_lookup(const std::string &host_name, int ipv) //ipv: default=4
{
    std::vector<std::string> output;
 
    struct addrinfo hints, *res, *p;
    int status, ai_family;
    char ip_address[INET6_ADDRSTRLEN];
 
    ai_family = ipv==6 ? AF_INET6 : AF_INET; //v4 vs v6?
    ai_family = ipv==0 ? AF_UNSPEC : ai_family; // AF_UNSPEC (any), or chosen
    memset(&hints, 0, sizeof hints);
    hints.ai_family = ai_family; 
    hints.ai_socktype = SOCK_STREAM;
 
    if ((status = getaddrinfo(host_name.c_str(), NULL, &hints, &res)) != 0) {
        //cerr << "getaddrinfo: "<< gai_strerror(status) << endl;
        return output;
    }
 
    //std::cout << "DNS Lookup: " << host_name << " ipv:" << ipv << endl;
 
    for(p = res;p != NULL; p = p->ai_next) {
        void *addr;
        if (p->ai_family == AF_INET) { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
        } else { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
        }
 
        // convert the IP to a std::string
        inet_ntop(p->ai_family, addr, ip_address, sizeof ip_address);
        output.push_back(ip_address);
    }
 
    freeaddrinfo(res); // free the linked list
 
    return output;
}

bool is_ipv6_address(const std::string& str)
{
    struct sockaddr_in6 sa;
    return inet_pton(AF_INET6, str.c_str(), &(sa.sin6_addr))!=0;
}

bool is_ipv4_address(const std::string& str)
{
    struct sockaddr_in sa;
    return inet_pton(AF_INET, str.c_str(), &(sa.sin_addr))!=0;
}

int socket_connect(std::string ip_address, int port)
{
    int err=-1,sd=-1;
    struct sockaddr_in sa;
 
    memset (&sa, '\0', sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = inet_addr (ip_address.c_str());   /* Server IP */
    sa.sin_port        = htons     (port);   /* Server Port number */
 
    sd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sd)
    {
        err = ::connect(sd, (struct sockaddr*) &sa, sizeof(sa));
    }
    if (err!=-1)//success
    {
        return sd;
    }
    std::cout << "socket connect error: " << std::endl;
    return -1;
    //if (errno==EINPROGRESS) { return 0; }//errno is a global set by connect
}

void download(const std::string& url, buffer& buf)
{
    int ipv,port;
    std::string protocol, domain, path, query, url_port;
    std::vector<std::string> ip_addresses;
 
    int offset = 0;
    size_t pos1,pos2,pos3,pos4;
    offset = offset==0 && url.compare(0, 8, "https://")==0 ? 8 : offset;
    offset = offset==0 && url.compare(0, 7, "http://" )==0 ? 7 : offset;
    pos1 = url.find_first_of('/', offset+1 );
    path = pos1==std::string::npos ? "" : url.substr(pos1);
    domain = std::string( url.begin()+offset, pos1 != std::string::npos ? url.begin()+pos1 : url.end() );
    path = (pos2 = path.find("#"))!=std::string::npos ? path.substr(0,pos2) : path;
    url_port = (pos3 = domain.find(":"))!=std::string::npos ? domain.substr(pos3+1) : "";
    domain = domain.substr(0, pos3!=std::string::npos ? pos3 : domain.length());
    protocol = offset > 0 ? url.substr(0,offset-3) : "";
    query = (pos4 = path.find("?"))!=std::string::npos ? path.substr(pos4+1) : "";
    path = pos4!=std::string::npos ? path.substr(0,pos4) : path;
 
    if (query.length()>0)
    {
        path.reserve( path.length() + 1 + query.length() );
        path.append("?").append(query);
    }
    if (url_port.length()==0 && protocol.length()>0)
    {
        url_port = protocol=="http" ? "80" : "443";
    }
    if (domain.length()>0 && !is_ipv6_address(domain))
    {
        if (is_ipv4_address(domain))
        {
            ip_addresses.push_back(domain);
        }
        else //if (!is_ipv4_address(domain))
        {
            ip_addresses = dns_lookup(domain, ipv=4);
        }
    }
    if (ip_addresses.size()>0)
    {
        port = std::stoi(url_port);
        
        std::string request  = "GET " + path + " HTTP/1.1\r\n";
        request += "Host: " + domain + "\r\n\r\n";
 
        for(int i=0,r=0, ix=ip_addresses.size(); i<ix && r==0; i++)
        {
            r = http_get(request, ip_addresses[i], port, buf);
        }
    }
}

std::string header_value(const std::string& full_header, const std::string& header_name)
{
    size_t pos = full_header.find(header_name);//case sensitive but probably shouldn't be
    std::string r;
    if (pos!=std::string::npos)
    {
        size_t begin = full_header.find_first_not_of(": ", pos + header_name.length());
        size_t until = full_header.find_first_of("\r\n\t ", begin + 1);
        if (begin!=std::string::npos && until!=std::string::npos)
        {
            r = full_header.substr(begin,until-begin);
        }
    }
    return r;
}

int http_get(const std::string& request, const std::string& ip_address, int port, buffer& buf)
{
    std::string header;
    char delim[] = "\r\n\r\n";
    char buffer[16384];

    int bytes_received=-1;
    int bytes_sofar=0;
    int bytes_expected=-1;
    int state=0;
 
    int sd = socket_connect(ip_address, port);
    if (sd > 0) 
    {
        ::send(sd, request.c_str(), request.length(), 0);
        while (bytes_sofar!=bytes_expected && (bytes_received = ::recv(sd, buffer, sizeof(buffer), 0))>0)
        {
            int body_index = 0;
            if (state + 1 < (signed int)sizeof(delim))//read header
            {
                int i = 0;
                for(; i < bytes_received && state + 1 < (signed int)sizeof(delim); i++)
                {
                    header += buffer[i];
                    state = buffer[i]==delim[state] ? state+1 : 0;
                }
                
                if(state == sizeof(delim)-1) {
                    bytes_received -= i;
                    body_index = i;
                }
            }
            if (bytes_expected==-1 && state==sizeof(delim)-1) //parse header
            {
                bytes_expected=-2;
                std::string h = header;
                std::stringstream(header_value(h, "Content-Length"))>> bytes_expected;
            }
            if (state==sizeof(delim)-1)//read body
            {
                bytes_sofar+=bytes_received;
                buf.append(buffer+body_index, bytes_received);
            }
        }
        
        ::close(sd);
    }
    return bytes_sofar;
}