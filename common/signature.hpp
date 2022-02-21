/*
    Socle - Socket Library Ecosystem
    Copyright (c) 2014, Ales Stibal <astib@mag0.net>, All rights reserved.

    This library  is free  software;  you can redistribute  it and/or
    modify  it  under   the  terms of the  GNU Lesser  General Public
    License  as published by  the   Free Software Foundation;  either
    version 3.0 of the License, or (at your option) any later version.
    This library is  distributed  in the hope that  it will be useful,
    but WITHOUT ANY WARRANTY;  without  even  the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
    
    See the GNU Lesser General Public License for more details.
    
    You  should have received a copy of the GNU Lesser General Public
    License along with this library.
*/

#ifndef SIGNATURE_HPP
 #define SIGNATURE_HPP

#include <string>
#include <regex>
#include <vector>
#include <tuple>
#include <optional>

#include <buffer.hpp>
#include <display.hpp>

#include <log/logger.hpp>
#include <log/logan.hpp>
#include <ranges.hpp>


template <class SourceType>
class Flow {

    using vector_type = std::vector<std::pair<SourceType,std::unique_ptr<buffer>>>;

    vector_type flow_; // store flow data ... ala follow tcp stream :)
                                     // Flowdata::side_ doesn't have to be necesarilly L or R
    std::vector<int> update_counters_;
                     
    int domain_ = SOCK_STREAM;  // if flow is not stream, data same-side chunks are stored separately

    logan_lite log;
public:
    unsigned int exchanges = 0; // count how many times flow changed side

    explicit Flow() {
        log = logan::create("flow");
    }

    inline void domain(int domain) { domain_ = domain; };
    inline int domain() const { return domain_ ; };

    vector_type& flow() { return flow_; }
    vector_type const& cflow() const { return flow_; }

    vector_type& operator() () { return flow(); }

    std::size_t size() const { return flow_.size(); }
    unsigned int append(SourceType src,buffer& b) { return append(src,b.data(),b.size());};
    unsigned int append(SourceType src,buffer* pb) { return append(src,pb->data(),pb->size());};
    unsigned int append(SourceType src,const void* data, size_t len) {
        if(flow_.size() == 0) {

            _dia("New flow init: side: %c: %d bytes",src,len);
            _dum("New flow init: side: %c: incoming  data:\n%s",src,hex_dump((unsigned char*)data,len).c_str());

            flow_.emplace_back(std::make_pair(src, new buffer(data,len)));
            update_counters_.push_back(1);
        }
        else if (flow_.back().first == src) {

            _dia("Flow::append: to current side: %c: %d bytes", src, len);
            _dum("Flow::append: to current side: %c: incoming  data:\r\n%s", src,
                    hex_dump((unsigned char*)data,  len > 128 ? 128 : static_cast<int>(len), 4, 0, true).c_str());
            
            if(domain() == SOCK_STREAM) {
                flow_.back().second->append(data,len);
                int& counter_ref = update_counters_.back();
                counter_ref++;
            }
            else {
                _dia("Flow::append: datagrams, packetized (new buffer on same side)");

                flow_.emplace_back(std::make_pair(src, new buffer(data,len)));
                update_counters_.push_back(1);
            }
        }
        else if (flow_.back().first != src) {
            _dia("Flow::append: to new side: %c: %d bytes", src, len);
            _dum("Flow::append: to new side: %c: incoming data:\r\n%s", src,
                    hex_dump((unsigned char*)data,len > 128 ? 128 : static_cast<int>(len), 4, 0, true).c_str());

            flow_.emplace_back(std::make_pair(src, new buffer(data,len)));

            update_counters_.push_back(1);
            exchanges++;
        }
        
        return len;
    };
    
    buffer* at(SourceType t, int idx) const {
        int i = 0;
        for(auto it = flow_.begin() ; it < flow_.end(); ++it) {
            SourceType tt = it->first;
            buffer* ff = it->second;
            if (tt == t) {
                if(i == idx) {
                    return ff;
                }

                i++;
            }
        }
        
        return nullptr;
    }
    
    std::string hr(bool verbose=false) {
        std::stringstream r;
        r << string_format("0x%x: ", this);

        if( flow_.empty() ) {
            r << "<empty>";
        }
        else {
            for( unsigned int i = 0; i < flow_.size(); i++) {
                char s =  flow_.at(i).first;
                auto& b = flow_.at(i).second;

                int updates = 1;
                if(i < update_counters_.size()) updates = update_counters_.at(i);

                r << string_format("%c:%s[%d]", s, updates == 1 ? "" : string_format("<%d>:",updates).c_str(), b->size());
                if(verbose) {
                    r << string_format("\n%s\n", hex_dump(b.get()).c_str());
                }

                if(i+1 != flow_.size()) {
                    if(!verbose)
                        r << ", ";
                }
            }
        }
        
        return r.str();
    }
    
    virtual ~Flow() = default;
};


class baseMatch {
protected:
    std::string expr_;
    explicit baseMatch(const char* e): expr_(e) {};
    explicit baseMatch(std::string& e): expr_(e) {};

    baseMatch(std::string& e, unsigned int o, unsigned int b) : expr_(e), match_limits_offset(o), match_limits_bytes(b) { expr() = e; }  
public:
    // directly accessible match constrains
    unsigned int match_limits_offset = 0;
    unsigned int match_limits_bytes = 0;
    
    virtual ~baseMatch() = default;
    virtual range match(const char* str, size_t max_len = 0) = 0;
    virtual range match(buffer& b) {
        return match((const char*)b.data(),b.size());
    }
    
    std::string& expr() { return expr_; }

protected:
    logan_lite log {"flow.match"};
};

class simpleMatch : public baseMatch {

public:
    ~simpleMatch() override = default;
    explicit simpleMatch(const char* e) : baseMatch(e) { }
    explicit simpleMatch(std::string& e) : baseMatch(e) { }
    simpleMatch(std::string& e, unsigned int o, unsigned int b) : baseMatch(e,o,b) {}
    
    range match(const char* str, size_t len = 0) override {
        
        range result;
        
        auto s = std::string(str,len);
        _ext("simpleMatch::match: '%s', len='%d' ",hex_dump((unsigned char*)s.c_str(), static_cast<int>(len), 4, 0, true).c_str(), len);
        
        range loc = search_function(expr(),s);
        

        if(loc == NULLRANGE) {
            _deb("simpleMatch::match: <0,-1>");
            result = NULLRANGE;
            
        } else {
            int loc_pos = loc.first;
            int loc_len = loc.second;

            _deb("simpleMatch::match: <%d,%d>", loc_pos, loc_len);
            result = range( loc_pos, loc_pos + loc_len - 1 );
        }

        return result;
    };
        
    virtual range search_function(std::string &expr, std::string &str) { 
        auto where = str.find(expr);

        if(*log.level() >= DUM) {
            _dum("simpleMatch::search_function: \nexpr:\n%s\ndata:\r\n%s",expr.c_str(),
                    hex_dump((unsigned char*)str.c_str(), str.size() > 128 ? 128 : static_cast<int>(str.size()), 4, 0, true).c_str());
        }
        else {
            _deb("simpleMatch::search_function: \r\nexpr: '%s'", expr.c_str());
        }
        
        if (where == std::string::npos) {
            return NULLRANGE;
        } else {
            return range(where, str.size());
        }
    };
    
    virtual range operator() (const char* str, unsigned int max_len = 0) { return match(str,max_len); };
};


template <class SourceType>
class flowMatch {
    
public:
    explicit flowMatch() = default;

    std::string& name() { return name_; }

    const std::vector<std::pair<SourceType,baseMatch*>>& sig_chain() const { return signature_; }

private:
    std::string name_;                                                         
    std::vector<std::pair<SourceType,baseMatch*>>  signature_;                // series of L/R/X matches to be satisfied
    logan_lite log {"flow.match"};

public:    
    
    virtual ~flowMatch() {
        for( auto& match: signature_) {
            _deb("flowmatch::destructor: deleting signature %p", match.second);
            delete match.second;
            signature_.clear();
        }
    }
    
    void add(SourceType s, baseMatch* m) { 
            signature_.push_back(std::pair<SourceType,baseMatch*>(s,m));             
    };
    
    
    virtual vector_range match(Flow<SourceType>* f) {
        vector_range v;
        unsigned int p;
        
        bool b = match(f,v,p);
        if(b) {
            return v;
        }
        
        vector_range ff; 
        ff.push_back(NULLRANGE);
        return ff;
    }
    
    // state-aware match function - state is hold in 
    virtual bool match(Flow<SourceType>* f, vector_range& ret, unsigned int& sig_pos) {
        
        
        int flow_step = 0;
        
        // sanitize step if we have some result already.  Step always starts at LAST already examined
        // flow, NOT NEXT. We need to check if there are new data in the last flow.
        if (! ret.empty() ) {
            flow_step = ret.size() -1;
        }
        
        unsigned int cur_flow = flow_step;
        baseMatch* sig_match = nullptr;

        _deb("flowMatch::match: search flow from #%d/%d: %s :sig pos = %d/%d", flow_step, f->flow().size(),
                                                                                vrangetos(ret).c_str(),
                                                                                sig_pos,signature_.size());
        
        bool first_iter = true;
        SourceType last_src;
        for( ; cur_flow < f->flow().size() && sig_pos < signature_.size(); cur_flow++) {
            auto& ff = f->flow().at(cur_flow);
            
            SourceType ff_src = ff.first;
            auto&    ff_buf = ff.second;

            // init unknown type of source
            if(first_iter) {
                first_iter = false;
                last_src = ff_src;
            }
            
            bool direction_change = false;
            if(last_src != ff_src) {
                direction_change = true;
                last_src = ff_src;
            }
         
            // check size and boundaries
            SourceType   sig_src = signature_.at(sig_pos).first;

            sig_match = signature_.at(sig_pos).second;
            unsigned int sig_match_limit_offset = sig_match->match_limits_offset;
            unsigned int sig_match_limit_bytes = sig_match->match_limits_bytes;
            
            // don't attempt to match empty buffer
            if( ff_buf->empty() ) {
                continue;
            }
            
            if ( ff_src == sig_src ) {
                
                // create view which will reflect signature limits
                buffer ff_view = ff_buf->view();
                
                if(sig_match_limit_bytes > 0 || sig_match_limit_offset > 0) {
                    ff_view = ff_buf->view(
                            sig_match_limit_offset < ff_buf->size() ? sig_match_limit_offset : ff_buf->size() - 1,
                            sig_match_limit_bytes + sig_match_limit_offset < ff_buf->size() ? sig_match_limit_bytes : ff_buf->size()
                                        );
                }
                
                // DEBUGS
                _deb("flowMatch::match: flow %d/%d : dirchange: %d",cur_flow, f->flow().size(), direction_change);
                _deb("flowMatch::match: processing signature[%s]: %s", std::to_string(sig_src).c_str(), sig_match->expr().c_str());
                _deb("flowMatch::match: pattern[%s] view-size=%d", std::to_string(ff_src).c_str(), ff_view.size());

                _dum("flowMatch::match: data=\r\n%s", hex_dump(ff_view.data(), ff_view.size(), 4, 0, true).c_str());

                range r = sig_match->match((const char*)ff_view.data(),(unsigned int)ff_view.size());
                
                if( r != NULLRANGE) {
                    _deb("flowMatch::match: result: %s", rangetos(r).c_str());

                    if(cur_flow == (ret.size() - 1)) {
                        // if previous result was NULLRANGE, remove
                        ret.erase(ret.end());
                    }
                    
                    ret.push_back(r);
                    ++sig_pos;
                    _dia("flowMatch::match: interim match on signature[%s]: %s", std::to_string(sig_src).c_str(), sig_match->expr().c_str());

                }
                else {
                    // don't add another NULLRANGES if we are at last position which is NULLRANGE already
                    if(cur_flow != (ret.size() - 1)) {
                            ret.push_back(NULLRANGE);
                    }
                    _deb("flowMatch::match: interim nok");
                }
            }
            else {
                _deb("flowMatch::match: different direction, skipping.");
                if(cur_flow != (ret.size() - 1)) {
                        ret.push_back(NULLRANGE);
                }
            }
        }


        if(sig_pos > 0) {

            auto sig_size = signature_.size();

            // do a nice logging, but don't waste time when it's not needed
            if(*log.level() >= DIA) {

                std::string sig;
                if (sig_match)
                    sig = sig_match->expr();
                else
                    sig = "<unknown>";

                std::string muchly = "partial";
                if(sig_pos >= sig_size) {
                    muchly = "full";
                }

                _dia("flowMatch::match: %s result %d/%d: %s",  muchly.c_str(), sig_pos, sig_size, sig.c_str());
            }

            if(sig_pos >= sig_size) {
                return true;
            }

        } else {
            _deb("flowMatch::match: nok");
        }
        
        return false;
    }
};

class regexMatch : public simpleMatch {
protected:
    std::regex expr_comp_;
    
public:

    explicit regexMatch(std::string& e) : simpleMatch(e), expr_comp_(e) {}
    regexMatch(std::string& e, unsigned int o, unsigned int b) : simpleMatch(e,o,b), expr_comp_(e) {}

    
    // expr is ignored, regex is already compiled
    range search_function(std::string &expr, std::string &str) override {
        std::smatch m;
        if (std::regex_search ( str , m, expr_comp_ )) {

            _dum("regexMatch::search_function: \r\nexpr:\r\n%s\r\ndata:\r\n%s", expr.c_str(),
                 hex_dump((unsigned char *) str.c_str(), str.size(), 4, 0, true).c_str());
            _deb("regexMatch::search_function: matches %d times.", m.size());

            return range(m.position(0), m.str().size());
        }
        else {
            _deb("regexMatch::search_function: no match.");
        }

        return NULLRANGE;
    }
};




// typedef SignatureType<flowMatch<unsigned char>> duplexSignature;
typedef Flow<char> duplexFlow;
typedef flowMatch<char> duplexFlowMatch;


class flowMatchState {
protected:
    bool         hit_ = false;    
    vector_range ranges_;
    unsigned int sig_pos_ = 0;
    
public:
    bool& hit() { return hit_; }
    vector_range& result() { return ranges_; };
    
    bool update(duplexFlow* f, std::shared_ptr<duplexFlowMatch> const& signature) {
       return signature->match(f,ranges_,sig_pos_);
    }
};



struct SignatureTree {

    using sensorType = std::vector<std::pair<flowMatchState,std::shared_ptr<duplexFlowMatch>>>;

    static constexpr const unsigned int max_groups = 128;

    std::bitset<max_groups> filter_;
    std::array<std::shared_ptr<sensorType>, max_groups> sensors_;
    std::unordered_map<std::string, int> name_index;

    SignatureTree() = delete;
    explicit SignatureTree(int prealloc_count) {

        for(int i = 0; i < prealloc_count; ++i)
            group_add(true);
    }

    int group_add(bool allowed=false) noexcept  {
        last_alloc_index++;

        sensors_[last_alloc_index] = std::make_shared<sensorType>();
        // unnamed
        filter_.set(last_alloc_index, allowed);

        return last_alloc_index;
    }

    int group_add(const char* name, bool allowed=false) noexcept {
        last_alloc_index++;

        sensors_[last_alloc_index] = std::make_shared<sensorType>();
        filter_.set(last_alloc_index, allowed);
        name_index[name] = last_alloc_index;


        return last_alloc_index;
    }

    std::optional<unsigned int> group_index(const char* name) {
        if(name_index.find(name) != name_index.end()) {

            return name_index[name];
        }
        return std::nullopt;
    }

    std::shared_ptr<sensorType> group(const char* name, bool allowed_only=true) {
        auto index = group_index(name);
        if(index.has_value()) {
            if(allowed_only) {
                if(filter_.test(index.value())) {
                    return sensors_[index.value()];
                }
                return nullptr;
            }
            return sensors_[index.value()];
        }
        return nullptr;
    }

    inline int size() const { return last_alloc_index; }
    inline bool check(size_t index) const { return filter_.test(index); }
    inline void set(size_t index, bool val) noexcept { if (index < max_groups) filter_.set(index, val); } // check boundaries to not throw

    /// @brief add signature into requested named sensor
    /// @param sig 'sig' shared pointer with the signature
    /// @param group_name 'group_name' desired named sensor - will be created if it doesn't exist
    /// @param allowed 'allowed' set to true if created sensor shall be marked as allowed
    /// @return return true if a new sensor has been created
    bool signature_add(std::shared_ptr<duplexFlowMatch> sig, const char* group_name, bool allowed = false) {

        auto created = false;

        auto gi = group_index(group_name);
        if(not gi) {
            gi = group_add(group_name, allowed);
            created = true;
        }

        auto sensor = sensors_[gi.value_or(0)];
        sensor->emplace_back(flowMatchState(), sig);

        return created;
    }

    void reset() {
        last_alloc_index = -1;
        name_index.clear();



        std::for_each(sensors_.begin(), sensors_.end(), []( std::shared_ptr<sensorType >& x) { x.reset(); });
    }

private:
    int last_alloc_index = -1;
};

#endif