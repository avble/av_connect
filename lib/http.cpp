#include "http.hpp"

namespace http {
// void response::end() {
//   if (is_owning) {
//     os << make_status_line(this->result_) << "\r\n";
//     if (req.headers_["connection"] != "")
//       headers_["connection"] = req.headers_["connection"];

//     for (const auto kv : headers_)
//       os << kv.first << ": " << kv.second << "\r\n";

//     os << "content-Length: " << body_.size() << "\r\n";
//     if (body_.size() > 0) {
//       os << "\r\n";
//       os << body_;
//       base_->do_write();
//     } else {
//       os << "\r\n";
//       base_->do_write();
//     }
//   }
// }

// void response::chunk_start() {
//   if (is_owning) {
//     const std::lock_guard<std::mutex> lock(chunk_mutex);
//     // write header
//     headers_["transfer-encoding"] = "chunked";
//     headers_["connection"] = "keep-alive";
//     os << make_status_line(this->result_) << "\r\n";
//     HTTP_LOG_TRACE("%s", "Header: \n");
//     for (const auto kv : headers_) {
//       os << kv.first << ": " << kv.second << "\r\n";
//       HTTP_LOG_TRACE("%s:%s\n", kv.first.c_str(), kv.second.c_str());
//     }
//     os << "\r\n";
//     base_->do_write([](boost::system::error_code ec, std::size_t len) {});
//   }
// }

// void response::chunk_write(std::string chunk_data) {
//   if (is_owning) {
//     const std::lock_guard<std::mutex> lock(chunk_mutex);
//     os << std::hex << chunk_data.size() << "\r\n";
//     os << chunk_data << "\r\n";
//     base_->do_write([](boost::system::error_code ec, std::size_t len) {});
//   }
// }

// void response::chunk_end() {
//   if (is_owning) {
//     const std::lock_guard<std::mutex> lock(chunk_mutex);
//     os << std::hex << 0 << "\r\n";
//     os << "\r\n";
//     base_->do_write();
//   }
// }

} // namespace http
