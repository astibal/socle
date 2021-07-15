
#include <traflog/traflog.hpp>

namespace socle {

    trafLog::trafLog(baseProxy *p,const char* d_dir, const char* f_prefix, const char* f_suffix) :
    sobject(),
    proxy_(p),
    data_dir(d_dir),
    file_prefix(f_prefix),
    file_suffix(f_suffix),
    writer_key_l_("???:???"),
    writer_key_r_("???:???") {
        create_writer_key();

        if(!use_pool_writer) {
            writer_ = new fileWriter();
        } else {
            writer_ = threadedPoolFileWriter::instance();
        }
    }

    std::string trafLog::to_string(int verbosity) const {
        return string_format("trafLog: file=%s opened=%d",writer_key_.c_str(),writer_->opened());
    }

    trafLog::~trafLog() {

        if(writer_) {
            if(! writer_key_.empty()) {
                writer_->close(writer_key_);
            }
        }

        if(! use_pool_writer)
            delete writer_;
    };


    std::string trafLog::create_writer_key(char side) {

        if(! proxy_ ) {
            return "";
        }

        std::string lh;
        if(! proxy_->ls().empty()) {
            lh = proxy_->ls().at(0)->host();
        }
        else {
            if(! proxy_->lda().empty()) {
                lh = proxy_->lda().at(0)->host();
            }
        }

        std::string l;
        if(! proxy_->ls().empty() ) {
            l = proxy_->ls().at(0)->name();
        }
        else {
            if(! proxy_->lda().empty()) {
                l = proxy_->lda().at(0)->name();
            }
        }

        std::string r;
        if(! proxy_->rs().empty()) {
            r = proxy_->rs().at(0)->name();
        }
        else {
            if( ! proxy_->rda().empty()) {
                r = proxy_->rda().at(0)->name();
            }
        }

        if (proxy_->lsize() > 0) {
            host_l_ = lh;
        }

        if (side == 'L' || side == 'l') {

            if (proxy_->lsize() > 0 && proxy_->rsize() > 0 ) {
                return string_format("%s-%s",l.c_str(),r.c_str());
            }
            else if (proxy_->lsize() > 0) {
                return string_format("%s-%s",l.c_str(),"unknown");
            }
            else if (proxy_->rsize() > 0) {
                return string_format("%s-%s","unknown",r.c_str());
            }
            else {
                return std::string("unknown-unknown");
            }
        } else {
            if (proxy_->lsize() > 0 && proxy_->rsize() > 0 ) {
                return string_format("%s-%s",r.c_str(),l.c_str());
            }
            else if (proxy_->rsize() > 0) {
                return string_format("%s-%s",r.c_str(),"unknown");
            }
            else if (proxy_->lsize() > 0) {
                return string_format("%s-%s","unknown",l.c_str());
            }
            else {
                return std::string("unknown-unknown");
            }
        }
    }

    std::string trafLog::create_writer_key() {
        writer_key_l_ = create_writer_key('L');
        writer_key_r_ = create_writer_key('R');

        if(writer_key_l_.empty() || writer_key_r_.empty()) {
            return "";
        }

        mkdir(data_dir.c_str(),0750);

        std::string hostdir = data_dir+"/"+host_l_+"/";
        mkdir(hostdir.c_str(),0750);

        time_t now = time(nullptr);
        tm loc{};

        localtime_r(&now,&loc);

        std::string datedir = string_format("%d-%02d-%02d/", loc.tm_year+1900, loc.tm_mon+1, loc.tm_mday);
        mkdir((hostdir+datedir).c_str(),0750);

        std::string file_datepart = string_format("%02d-%02d-%02d_", loc.tm_hour, loc.tm_min, loc.tm_sec);

        std::stringstream ss;

        ss << hostdir << datedir << file_prefix << file_datepart << writer_key_l_ << "." << file_suffix;
        writer_key_ = ss.str();

        return writer_key_;
    }


    void trafLog::write(side_t side, std::string const& s) {

        timeval now{};
        gettimeofday(&now, nullptr);
        char d[64];
        memset(d,0,64);
        ctime_r(&now.tv_sec,d);

        std::string k1;
        std::string k2;

        switch (side) {
            case side_t::RIGHT:
                k1 = writer_key_r_;
                k2 = writer_key_l_;
                break;
            case side_t::LEFT:
                k1 = writer_key_l_;
                k2 = writer_key_r_;
                break;
        }

        if(! writer_->opened() ) {
            if (writer_->open(writer_key_)) {
                _dia("writer '%s' created",writer_key_l_.c_str());
            } else {
                _err("write '%s' failed to open dump file!",writer_key_l_.c_str());
            }
        }

        if (writer_->opened()) {

            std::stringstream ss;
            ss << d << "+" << now.tv_usec << ": "<< k1 << "(" << k2 << ")\n";
            ss << s << '\n';

            writer_->write(writer_key_, ss.str());

        } else {
            _err("cannot write to stream, writer not opened.");
        }
    }
}
