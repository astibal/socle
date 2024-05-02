#include <set>
#include <sstream>

#include "socle/common/stringops.hpp"


void string_tags_update(std::vector<std::string>& tagvec, std::string const& str) {

    auto tags = std::set<std::string>(tagvec.begin(), tagvec.end());

    std::stringstream ss;
    char op = '+';
    std::string prev_token;


    for(unsigned int i = 0; i < str.length() ; i++) {

        if(str[i] == '=') {
            tags.clear();
            ss = std::stringstream();
            prev_token.clear();
        }
        else if(str[i] == '+' or str[i] == '-') {

            if(op == '-') {
                if(not prev_token.empty())
                    tags.erase(prev_token);
            }
            else {
                if (not prev_token.empty())
                    tags.insert(prev_token);
            }
            op = str[i];
            ss = std::stringstream();
            prev_token.clear();
        }
        else {

            auto c = str[i];
            if(isalnum(c) or c == '.' or c == '_' or c == '/') {
                ss << str[i];
                prev_token = ss.str();
            }
        }
    }

    if(op == '-') {
        if(not prev_token.empty())
            tags.erase(prev_token);
    }
    else {
        if (not prev_token.empty())
            tags.insert(prev_token);
    }


    tagvec = { tags.begin(), tags.end() };
}


std::vector<std::string> string_tags(std::string const& str) {
    std::vector<std::string> tagvec;
    string_tags_update(tagvec, str);
    return tagvec;
}
