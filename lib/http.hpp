#include "io_base.hpp"
#include "log.hpp"

#include "helper.hpp"
#include "json.hpp"

#include <boost/asio.hpp>
#include <http_parser.h>

#include <algorithm>
#include <any>
#include <cinttypes>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <tuple>
// #include <unistd.h>
#include <any>
#include <queue>
#include <unordered_map>
#include <utility>
#include <vector>

// #include <sys/queue.h>

#ifdef _MSC_VER
#include <ciso646>
#endif

using boost::asio::ip::tcp;
using json = nlohmann::ordered_json;

// Module-specific log macros for HTTP module
#define HTTP_LOG_TRACE(...) log(LOG_TRACE, "HTTP", __VA_ARGS__)
#define HTTP_LOG_DEBUG(...) log(LOG_DEBUG, "HTTP", __VA_ARGS__)
#define HTTP_LOG_INFO(...) log(LOG_INFO, "HTTP", __VA_ARGS__)
#define HTTP_LOG_WARN(...) log(LOG_WARN, "HTTP", __VA_ARGS__)
#define HTTP_LOG_ERROR(...) log(LOG_ERROR, "HTTP", __VA_ARGS__)

#ifdef NDEBUG
#define HTTP_ASSERT(condition, ...) ((void)0)
#else
#define HTTP_ASSERT(condition, ...)                                            \
  do {                                                                         \
    if (!(condition)) {                                                        \
      HTTP_LOG_ERROR("Assertion failed at %s:%d", __FILE__, __LINE__);         \
      if (sizeof(#__VA_ARGS__) > 1) {                                          \
        HTTP_LOG_ERROR(__VA_ARGS__);                                           \
      }                                                                        \
      std::abort();                                                            \
    }                                                                          \
  } while (0)
#endif

namespace http {
class base_data {
public:
  virtual ~base_data() = default;
  base_data() = default;

private:
  base_data(const base_data &) = delete;
  base_data &operator=(const base_data &) = delete;
};

} // namespace http

struct logger_function_trace {
public:
  logger_function_trace(std::string cls_, std::string func_)
      : cls(cls_), func(func_) {
    HTTP_LOG_TRACE("%s:%s ENTER\n", cls.c_str(), func.c_str());
  }

  ~logger_function_trace() {
    HTTP_LOG_TRACE("%s:%s LEAVE\n", cls.c_str(), func.c_str());
  }

private:
  const std::string cls;
  const std::string func;
};

#define HTTP_LOG_TRACE_FUNCTION                                                \
  logger_function_trace x_trace_123_("", __FUNCTION__);
#define HTTP_TRACE_CLS_FUNC_TRACE                                              \
  logger_function_trace x_trace_123_(typeid(this).name(), __FUNCTION__);

// forward declaration
namespace http {
enum class method;
}

namespace std {
template <> class hash<std::tuple<http::method, std::string>> {
public:
  std::size_t operator()(const std::tuple<http::method, std::string> &s) const {
    std::size_t h1 = std::hash<int>{}(static_cast<int>(std::get<0>(s)));
    std::size_t h2 = std::hash<std::string>{}(std::get<1>(s));
    return h1 ^ h2;
  }
};

template <> struct equal_to<std::tuple<http::method, std::string>> {
  bool operator()(const std::tuple<http::method, std::string> &lhs,
                  const std::tuple<http::method, std::string> &rhs) const {
    return (std::get<0>(lhs) == std::get<0>(rhs)) and
           (std::get<1>(lhs) == std::get<1>(rhs));
  }
};

} // namespace std

namespace http {

class response;
class request;

enum class status_code {
  // 1xx Informational
  continue_ = 100,
  switching_protocols = 101,

  // 2xx Success
  ok = 200,
  created = 201,
  accepted = 202,
  non_authoritative_info = 203,
  no_content = 204,
  reset_content = 205,
  partial_content = 206,

  // 3xx Redirection
  multiple_choices = 300,
  moved_permanently = 301,
  found = 302,
  see_other = 303,
  not_modified = 304,
  use_proxy = 305,
  unused = 306, // Reserved, not used
  temporary_redirect = 307,

  // 4xx Client Error
  bad_request = 400,
  unauthorized = 401,
  payment_required = 402,
  forbidden = 403,
  not_found = 404,
  method_not_allowed = 405,
  not_acceptable = 406,
  proxy_auth_required = 407,
  request_timeout = 408,
  conflict = 409,
  gone = 410,
  length_required = 411,
  precondition_failed = 412,
  payload_too_large = 413,
  uri_too_long = 414,
  unsupported_media_type = 415,
  range_not_satisfiable = 416,
  expectation_failed = 417,

  // 5xx Server Error
  internal_server_error = 500,
  not_implemented = 501,
  bad_gateway = 502,
  service_unavailable = 503,
  gateway_timeout = 504,
  http_version_not_supported = 505
};

inline std::string status_code_to_string(status_code code) {
  switch (code) {
  // 1xx
  case status_code::continue_:
    return "Continue";
  case status_code::switching_protocols:
    return "Switching Protocols";

  // 2xx
  case status_code::ok:
    return "OK";
  case status_code::created:
    return "Created";
  case status_code::accepted:
    return "Accepted";
  case status_code::non_authoritative_info:
    return "Non-Authoritative Information";
  case status_code::no_content:
    return "No Content";
  case status_code::reset_content:
    return "Reset Content";
  case status_code::partial_content:
    return "Partial Content";

  // 3xx
  case status_code::multiple_choices:
    return "Multiple Choices";
  case status_code::moved_permanently:
    return "Moved Permanently";
  case status_code::found:
    return "Found";
  case status_code::see_other:
    return "See Other";
  case status_code::not_modified:
    return "Not Modified";
  case status_code::use_proxy:
    return "Use Proxy";
  case status_code::unused:
    return "Unused";
  case status_code::temporary_redirect:
    return "Temporary Redirect";

  // 4xx
  case status_code::bad_request:
    return "Bad Request";
  case status_code::unauthorized:
    return "Unauthorized";
  case status_code::payment_required:
    return "Payment Required";
  case status_code::forbidden:
    return "Forbidden";
  case status_code::not_found:
    return "Not Found";
  case status_code::method_not_allowed:
    return "Method Not Allowed";
  case status_code::not_acceptable:
    return "Not Acceptable";
  case status_code::proxy_auth_required:
    return "Proxy Authentication Required";
  case status_code::request_timeout:
    return "Request Timeout";
  case status_code::conflict:
    return "Conflict";
  case status_code::gone:
    return "Gone";
  case status_code::length_required:
    return "Length Required";
  case status_code::precondition_failed:
    return "Precondition Failed";
  case status_code::payload_too_large:
    return "Payload Too Large";
  case status_code::uri_too_long:
    return "URI Too Long";
  case status_code::unsupported_media_type:
    return "Unsupported Media Type";
  case status_code::range_not_satisfiable:
    return "Range Not Satisfiable";
  case status_code::expectation_failed:
    return "Expectation Failed";

  // 5xx
  case status_code::internal_server_error:
    return "Internal Server Error";
  case status_code::not_implemented:
    return "Not Implemented";
  case status_code::bad_gateway:
    return "Bad Gateway";
  case status_code::service_unavailable:
    return "Service Unavailable";
  case status_code::gateway_timeout:
    return "Gateway Timeout";
  case status_code::http_version_not_supported:
    return "HTTP Version Not Supported";

  default:
    return "Unknown";
  }
}
enum class method {
  del = 0,
  get,
  head,
  post,
  put,
  option = 6,
};

#if 0 // plan change
enum class method
{
    options = 0,
    get,
    head,
    post,
    put,
    delete_,
    trace,
    connect
};

inline std::string method_to_string(method m)
{
    switch (m)
    {
        case method::options: return "OPTIONS";
        case method::get: return "GET";
        case method::head: return "HEAD";
        case method::post: return "POST";
        case method::put: return "PUT";
        case method::delete_: return "DELETE";
        case method::trace: return "TRACE";
        case method::connect: return "CONNECT";
        default: return "UNKNOWN";
    }
}

#endif

inline std::string get_status_code_msg(status_code code_) {
  if (code_ == status_code::ok)
    return "OK";

  if (code_ == status_code::not_found)
    return "Not Found";

  return "Internal";
}

// i.e HTTP/1.1 200 OK
inline std::string make_status_line(status_code code, std::string msg = "") {
  std::string status_line = "HTTP/1.1 ";
  status_line += std::to_string(static_cast<int>(code)) + " " +
                 (msg == "" ? get_status_code_msg(code) : msg);
  return status_line;
}

inline int http_parser_get_major(http_parser *parser) {
  return parser->http_major;
}

inline int http_parser_get_minor(http_parser *parser) {
  return parser->http_minor;
}

inline method http_parser_get_method(http_parser *parser) {
  return static_cast<method>(static_cast<int>(parser->method));
}

class request {
public:
  request() = delete;
  request(request &other) = delete;
  request &operator=(request &other) = delete;
  request &operator=(request &&other) = delete;

  request(request &&other) {
    uri_path = other.uri_path;
    major = other.major;
    minor = other.minor;
    method_ = other.method_;
    headers_ = std::move(other.headers_);
    body_ = std::move(other.body_);

    other.is_owning = false;
    is_owning = true;
  }

  template <class T> request(T parser) {
    major = http_parser_get_major(parser);
    minor = http_parser_get_minor(parser);
    method_ = http_parser_get_method(parser);
  }

  template <class T>
  request(T parser, std::string _uri_path) : request(parser) {
    uri_path = _uri_path;
  }

  template <class T>
  request(T parser, std::string _uri_path,
          std::unordered_map<std::string, std::string> &&_header,
          std::string _body)
      : request(parser, _uri_path) {
    headers_ = std::move(_header);
    body_ = _body;
  }

  const std::string &get_uri_path() { return uri_path; }
  const method &get_method() const { return method_; }
  const std::string &get_header(std::string header_key) {
    return headers_[header_key];
  }
  const std::string &body() const { return body_; }

  ~request() {}

private:
  std::string uri_path;
  method method_;
  char major;
  char minor;
  std::unordered_map<std::string, std::string> headers_;
  std::string body_;

  bool is_owning;

  friend class response;
};

class response : public std::enable_shared_from_this<response> {

  // type definitions
  enum class response_state {
    PENDING,  // Initial state, response not sent yet
    STARTED,  // Headers sent (for chunked responses)
    COMPLETED // Response fully sent
  };

  class base {
  public:
    base() = default;
    base(const base &other) = delete;
    base &operator=(const base &other) = delete;
    virtual ~base() = default;

    virtual void do_write(
        std::function<void(boost::system::error_code, std::size_t)>) = 0;
    virtual void do_write() = 0;
    virtual uint64_t session_id() = 0;
    virtual std::unique_ptr<base_data> &get_session_data() = 0;
  };

  template <typename T> class wrapper : public base {
  public:
    wrapper(const wrapper &other) = delete;
    wrapper &operator=(const wrapper &other) = delete;
    wrapper(wrapper &&other) = default;
    wrapper(std::weak_ptr<T> p_) : p(std::move(p_)) {}

    void do_write(
        std::function<void(boost::system::error_code, std::size_t)> on_write) {
      if (auto w_p = p.lock()) {
        w_p->do_write(on_write);
      }
    }

    void do_write() {
      if (auto w_p = p.lock()) {
        w_p->do_write();
      }
    }

    uint64_t session_id() {
      if (auto w_p = p.lock()) {
        return w_p->get_session_id();
      }

      return std::numeric_limits<uint64_t>::max();
    }

    std::unique_ptr<base_data> &get_session_data() {
      if (auto w_p = p.lock()) {
        return w_p->get_session_data();
      }
      throw std::runtime_error("hmmm");
    }

    ~wrapper() {}

    std::weak_ptr<T> p;
  };

  enum class chunk_operation_type { START, WRITE, END };

  struct chunk_operation {
    chunk_operation_type type;
    std::string data;
    std::function<void(bool)> callback;
  };

public:
  response() = delete;
  response(const response &) = delete;
  response &operator=(const response &) = delete;
  response(response &&) = delete;
  response &operator=(response &&) = delete;

  template <class T>
  static std::shared_ptr<response> create(std::weak_ptr<T> connect_,
                                          request &&req_,
                                          boost::asio::streambuf &_out_buffer) {
    return std::shared_ptr<response>(
        new response(connect_, std::move(req_), _out_buffer));
  }

  ~response() {
    if (state_ == response_state::PENDING) {
      HTTP_LOG_WARN("Response was destroyed without explicitly sending a "
                    "response. URI: %s. Sending default response.",
                    req.get_uri_path().c_str());
      send_default_response();
    }
  }

  status_code &result() { return result_; }

  void set_header(std::string header_key, std::string header_val) {
    std::transform(header_key.begin(), header_key.end(), header_key.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    headers_[header_key] = header_val;
  }

  uint64_t session_id() { return base_->session_id(); }

  std::unique_ptr<base_data> &get_session_data() {
    return base_->get_session_data();
  }

  void set_content(std::string _body, std::string content_type = "text/plain") {
    body_ = std::move(_body);
    headers_["content-type"] = content_type;
  }

  [[deprecated("use set_content(std::string , std::string) instead")]]
  void set_content(const char *_body, size_t len,
                   std::string content_type = "text/plain") {
    body_ = std::string(_body, len);
    headers_["content-type"] = content_type;
  }

  void end() {
    if (state_ == response_state::PENDING) {
      os << make_status_line(this->result_) << "\r\n";
      if (req.headers_["connection"] != "")
        headers_["connection"] = req.headers_["connection"];

      for (const auto kv : headers_)
        os << kv.first << ": " << kv.second << "\r\n";

      os << "content-Length: " << body_.size() << "\r\n";
      if (body_.size() > 0) {
        os << "\r\n";
        os << body_;
        base_->do_write();
      } else {
        os << "\r\n";
        base_->do_write();
      }
      state_ = response_state::COMPLETED;
    }
  }

  [[deprecated("Use chunk_start_async() instead")]]
  void chunk_start() {
    if (state_ == response_state::PENDING) {
      const std::lock_guard<std::mutex> lock(chunk_mutex);
      headers_["transfer-encoding"] = "chunked";
      headers_["connection"] = "keep-alive";
      os << make_status_line(this->result_) << "\r\n";
      for (const auto kv : headers_)
        os << kv.first << ": " << kv.second << "\r\n";
      os << "\r\n";
      base_->do_write([](boost::system::error_code ec, std::size_t len) {});
      state_ = response_state::STARTED;
    }
  }

  // void chunk_start_async(std::function<void(boost::system::error_code)>
  // callback = nullptr) {
  //   if (state_ != response_state::PENDING) {
  //     if (callback) callback(boost::system::errc::make_error_code(
  //         boost::system::errc::operation_not_permitted));
  //     return;
  //   }

  //   const std::lock_guard<std::mutex> lock(chunk_mutex);
  //   headers_["transfer-encoding"] = "chunked";
  //   headers_["connection"] = "keep-alive";
  //   os << make_status_line(this->result_) << "\r\n";
  //   for (const auto kv : headers_)
  //     os << kv.first << ": " << kv.second << "\r\n";
  //   os << "\r\n";

  //   base_->do_write([this, callback](boost::system::error_code ec,
  //   std::size_t len) {
  //     if (!ec) {
  //       state_ = response_state::STARTED;
  //     }
  //     if (callback) callback(ec);
  //   });
  // }

  [[deprecated("Use chunk_write_async() instead")]]
  void chunk_write(std::string chunk_data) {
    if (state_ == response_state::STARTED) {
      const std::lock_guard<std::mutex> lock(chunk_mutex);
      os << std::hex << chunk_data.size() << "\r\n";
      os << chunk_data << "\r\n";
      base_->do_write([](boost::system::error_code ec, std::size_t len) {});
    }
  }

  // void chunk_write_async(std::string chunk_data,
  //                       std::function<void(boost::system::error_code)>
  //                       callback = nullptr) {
  //   try_chunk_write(std::move(chunk_data), std::move(callback));
  // }

  [[deprecated("Use chunk_end_async() instead")]]
  void chunk_end() {
    if (state_ == response_state::STARTED) {
      const std::lock_guard<std::mutex> lock(chunk_mutex);
      os << std::hex << 0 << "\r\n";
      os << "\r\n";
      base_->do_write();
      state_ = response_state::COMPLETED;
    }
  }

  void chunk_start_async(std::function<void(bool)> callback = nullptr) {
    HTTP_LOG_TRACE_FUNCTION {
      printf("[DEBUG] %s:%d \n", __func__, __LINE__);
      std::lock_guard<std::mutex> lock(chunk_queue_mutex_);
      chunk_queue_.push({chunk_operation_type::START, "", callback});
    }
    process_chunk_queue();
    printf("[DEBUG] %s:%d \n", __func__, __LINE__);
  }

  void chunk_write_async(std::string data,
                         std::function<void(bool)> callback = nullptr) {
    HTTP_LOG_TRACE_FUNCTION

    {
      std::lock_guard<std::mutex> lock(chunk_queue_mutex_);
      chunk_queue_.push(
          {chunk_operation_type::WRITE, std::move(data), callback});
    }
    process_chunk_queue();
  }

  void chunk_end_async(std::function<void(bool)> callback = nullptr) {
    HTTP_LOG_TRACE_FUNCTION {
      std::lock_guard<std::mutex> lock(chunk_queue_mutex_);
      chunk_queue_.push({chunk_operation_type::END, "", callback});
    }
    process_chunk_queue();
  }

  void event_source_start() {
    // headers_["content-type"] = "text/event-stream";
    // headers_["connection"] = "timeout=5, max=5";
    // chunk_start();
    chunk_start_async();
  }

  void event_source_oai_end() {
    if (state_ != response_state::STARTED)
      return;

    static const std::string oai_end_chunk = "data: [DONE]\n\n";
    chunk_write_async(oai_end_chunk, [self = shared_from_this()](bool result) {
      if (result) {
        self->chunk_end_async();
      }
    });
  }

  request &reqwest() { return req; }

  bool is_completed() const { return state_ == response_state::COMPLETED; }

  void
  set_default_response(std::string body,
                       status_code code = status_code::internal_server_error) {
    default_response_body_ = std::move(body);
    default_response_code_ = code;
  }

  // New chunk API
  // void set_queue_limit(size_t limit) {
  //   queue_size_limit_ = limit;
  // }

  // bool is_queue_full() const {
  //   return current_queue_size_ >= queue_size_limit_;
  // }

  // bool try_chunk_write(const std::string& chunk_data,
  //                     std::function<void(boost::system::error_code)> callback
  //                     = nullptr) {
  //   if (state_ != response_state::STARTED) {
  //     if (callback) callback(boost::system::errc::make_error_code(
  //         boost::system::errc::operation_not_permitted));
  //     return false;
  //   }

  //   if (current_queue_size_ + chunk_data.size() > queue_size_limit_) {
  //     return false;
  //   }

  //   const std::lock_guard<std::mutex> lock(chunk_mutex);
  //   chunk_queue_.emplace(chunk_data, std::move(callback));
  //   current_queue_size_ += chunk_data.size();

  //   if (!is_writing_) {
  //     process_chunk_queue();
  //   }
  //   return true;
  // }

private:
  template <class T>
  response(std::weak_ptr<T> connect_, request &&req_,
           boost::asio::streambuf &_out_buffer)
      : req(std::move(req_)), os(&_out_buffer),
        base_(std::make_unique<wrapper<T>>(connect_)) {
    result_ = status_code::ok;
    major = req_.major;
    minor = req_.minor;
    headers_["server"] = "av_connect";
    state_ = response_state::PENDING;
  }

  void send_default_response() noexcept {
    if (state_ == response_state::PENDING) {
      result_ = default_response_code_;
      set_content(default_response_body_);
      end();
    }
  }

  void process_chunk_queue() {
    // Try to acquire processing flag atomically
    bool expected = false;
    if (!chunk_processing_.compare_exchange_weak(expected, true)) {
      // Another thread is already processing
      return;
    }

    // Get next operation without holding mutex for long
    chunk_operation op;
    bool has_operation = false;
    {
      std::lock_guard<std::mutex> lock(chunk_queue_mutex_);
      if (!chunk_queue_.empty()) {
        op = std::move(chunk_queue_.front());
        chunk_queue_.pop();
        has_operation = true;
      }
    }

    if (!has_operation) {
      chunk_processing_ = false;
      return;
    }

    auto self = shared_from_this();
    auto completion_handler =
        [self, callback = op.callback](boost::system::error_code ec,
                                       std::size_t len) {
          bool success = !ec;
          if (callback)
            callback(success);

          // Release processing flag and schedule next operation
          self->chunk_processing_ = false;

          // Post continuation to event loop to avoid recursive calls
          boost::asio::post(io_context::ioc,
                            [self]() { self->process_chunk_queue(); });
        };

    execute_operation(op, completion_handler);
  }

  void
  execute_operation(const chunk_operation &op,
                    std::function<void(boost::system::error_code, std::size_t)>
                        completion_handler) {
    auto self = shared_from_this();

    switch (op.type) {
    case chunk_operation_type::START: {
      if (state_ != response_state::PENDING) {
        if (op.callback)
          op.callback(false);
        chunk_processing_ = false;
        boost::asio::post(io_context::ioc,
                          [self]() { self->process_chunk_queue(); });
        return;
      }

      headers_["transfer-encoding"] = "chunked";
      headers_["connection"] = "keep-alive";
      os << make_status_line(this->result_) << "\r\n";
      for (const auto &kv : headers_)
        os << kv.first << ": " << kv.second << "\r\n";
      os << "\r\n";

      base_->do_write([self, completion_handler](boost::system::error_code ec,
                                                 std::size_t len) {
        if (!ec) {
          self->state_ = response_state::STARTED;
        }
        completion_handler(ec, len);
      });
      break;
    }

    case chunk_operation_type::WRITE: {
      if (state_ != response_state::STARTED) {
        if (op.callback)
          op.callback(false);
        chunk_processing_ = false;
        boost::asio::post(io_context::ioc,
                          [self]() { self->process_chunk_queue(); });
        return;
      }

      os << std::hex << op.data.size() << "\r\n";
      os << op.data << "\r\n";
      base_->do_write(completion_handler);
      break;
    }

    case chunk_operation_type::END: {
      if (state_ != response_state::STARTED) {
        if (op.callback)
          op.callback(false);
        chunk_processing_ = false;
        boost::asio::post(io_context::ioc,
                          [self]() { self->process_chunk_queue(); });
        return;
      }

      os << std::hex << 0 << "\r\n";
      os << "\r\n";
      base_->do_write([self, completion_handler](boost::system::error_code ec,
                                                 std::size_t len) {
        if (!ec) {
          self->state_ = response_state::COMPLETED;
        }
        completion_handler(ec, len);
      });
      break;
    }
    }
  }

private:
  response_state state_ = response_state::PENDING;
  request req;
  status_code result_;
  char major;
  char minor;
  std::unordered_map<std::string, std::string> headers_;
  std::string body_;
  std::string default_response_body_ = "No response was explicitly sent";
  status_code default_response_code_ = status_code::internal_server_error;

  std::ostream os;
  std::unique_ptr<base> base_;
  std::mutex chunk_mutex;

  // Queue management
  // std::queue<chunk_queue_entry> chunk_queue_;
  // size_t queue_size_limit_ = std::numeric_limits<size_t>::max();
  // size_t current_queue_size_ = 0;
  // bool is_writing_ = false;

  std::queue<chunk_operation> chunk_queue_;
  std::mutex chunk_queue_mutex_;
  std::atomic<bool> chunk_processing_{false};
};

class session : public std::enable_shared_from_this<session> {
  struct internal_wrapper {
    internal_wrapper(std::shared_ptr<session> _p) { p_session = _p; }

    internal_wrapper(const internal_wrapper &other) {
      p_session = other.p_session;
    }

    std::shared_ptr<session> p_session;
  };

  enum { max_length = 102400 };

public:
  session(tcp::socket socket,
          std::function<void(std::shared_ptr<response>)> _handler)
      : socket_(std::move(socket)), handler(_handler) {
    HTTP_TRACE_CLS_FUNC_TRACE
    data_len = 0;
    is_request_parsed = false;
    std::memset(&settings, 0, sizeof settings);
  }

  session(tcp::socket socket,
          std::function<void(std::shared_ptr<response>)> _handler,
          uint64_t _session_id)
      : session(std::move(socket), _handler) {
    HTTP_TRACE_CLS_FUNC_TRACE
    session_id = _session_id;
  }

  ~session(){HTTP_TRACE_CLS_FUNC_TRACE}

  uint64_t get_session_id() {
    return session_id;
  }

  void start() {
    HTTP_TRACE_CLS_FUNC_TRACE
    static http_data_cb llhttp_on_uri =
        [](http_parser *_http_parser, const char *at, size_t length) -> int {
      internal_wrapper *wrapper_ = (internal_wrapper *)_http_parser->data;
      auto self = wrapper_->p_session;
      self->uri = std::string(at, length);
      return 0;
    };

    static http_data_cb llhttp_on_header_field =
        [](http_parser *_http_parser, const char *at, size_t length) -> int {
      internal_wrapper *wrapper_ = (internal_wrapper *)_http_parser->data;
      auto self = wrapper_->p_session;

      self->header_field = std::string((char *)at, length);
      std::transform(self->header_field.begin(), self->header_field.end(),
                     self->header_field.begin(),
                     [](unsigned char c) { return std::tolower(c); });
      return 0;
    };

    static http_data_cb llhttp_on_header_value =
        [](http_parser *_http_parser, const char *at, size_t length) -> int {
      internal_wrapper *wrapper_ = (internal_wrapper *)_http_parser->data;
      auto self = wrapper_->p_session;

      self->headers[self->header_field] = std::string((char *)at, length);
      std::string &header_field_val = self->headers[self->header_field];
      std::transform(header_field_val.begin(), header_field_val.end(),
                     header_field_val.begin(),
                     [](unsigned char c) { return std::tolower(c); });

      return 0;
    };

    static http_data_cb llhttp_on_body =
        [](http_parser *_http_parser, const char *at, size_t length) -> int {
      internal_wrapper *wrapper_ = (internal_wrapper *)_http_parser->data;
      auto self = wrapper_->p_session;

      self->in_buffer.consume(self->in_buffer.size());
      std::ostream os(&self->in_buffer);
      os << std::string_view((char *)at, length);

      return 0;
    };

    static http_cb llhttp_on_message_complete =
        [](http_parser *_http_parser) -> int {
      internal_wrapper *wrapper_ = (internal_wrapper *)_http_parser->data;
      auto self = wrapper_->p_session;

      self->is_request_parsed = true;
      self->on_read(_http_parser);

      return 0;
    };

    settings.on_header_field = llhttp_on_header_field;
    settings.on_header_value = llhttp_on_header_value;
    settings.on_url = llhttp_on_uri;
    settings.on_body = llhttp_on_body;
    settings.on_message_complete = llhttp_on_message_complete;
    parser.data = new internal_wrapper(shared_from_this());

    do_read();
  }

  /*
  - Write and call complete function
  - is suitable for pattern <read> --> <write chunk-1> --> <write chunk-2> -->
  <write chunk-3> --> <write end-chunk> --> <read>
  */
  void do_write(
      std::function<void(boost::system::error_code, std::size_t)> on_write) {
    HTTP_TRACE_CLS_FUNC_TRACE
    auto on_write_ = [self(shared_from_this()), on_write](
                         boost::system::error_code ec, std::size_t size) {
      self->out_buffer.consume(self->out_buffer.size());
      on_write(ec, size);
    };

    boost::asio::async_write(
        socket_, boost::asio::buffer(out_buffer.data(), out_buffer.size()),
        on_write_);
  }

  /*
  - Write and then call do read request.
  - Is suitable for patter <read> --> <write> --> <read> --> <write> --> <read>
  */

  void do_write() {
    HTTP_TRACE_CLS_FUNC_TRACE
    auto self(shared_from_this());
    boost::asio::async_write(
        socket_, boost::asio::buffer(out_buffer.data(), out_buffer.size()),
        [self](boost::system::error_code ec, std::size_t /*length*/) {
          if (!ec) {
            self->out_buffer.consume(self->out_buffer.size());
            self->do_read();
          }
        });
  }

  std::unique_ptr<base_data> &get_session_data() { return data; }

private:
  void do_read() {
    HTTP_TRACE_CLS_FUNC_TRACE
    auto self(shared_from_this());

    socket_.async_read_some(
        boost::asio::buffer(&data_[0] + data_len, max_length),
        [this, self](boost::system::error_code ec, std::size_t length) {
          HTTP_LOG_TRACE("%s:  async_read_some's completion is called. with "
                         "info (rc: %d)\n",
                         __func__, static_cast<int>(ec.value()));

          if (ec.value() == 0) {
            self->data_len += length;
            is_request_parsed = false;
            http_parser_init(&parser, HTTP_BOTH);
            size_t return_size =
                http_parser_execute(&(self->parser), &(self->settings),
                                    self->data_, self->data_len);
            if (not is_request_parsed) {
              self->do_read();
            } else if (return_size < self->data_len) {
              std::memcpy(self->data_, self->data_ + return_size,
                          self->data_len - return_size);
            } else if (is_request_parsed) {
              self->uri = "";
              self->data_len = 0;
            }
          } else {
            internal_wrapper *p =
                reinterpret_cast<internal_wrapper *>(self->parser.data);
            delete p;
            HTTP_LOG_WARN("%s:%" PRIu64
                          " the reading (error: %d, sefl-cnt: %d)\n",
                          __func__, session_id, static_cast<int>(ec.value()),
                          self.use_count());
          }
        });
  }

  void on_read(http_parser *_http_parser) {
    HTTP_TRACE_CLS_FUNC_TRACE
    auto res = http::response::create(
        std::weak_ptr<session>(shared_from_this()),
        request(_http_parser, uri, std::move(headers),
                {(char *)in_buffer.data().data(), in_buffer.size()}),
        out_buffer);

    handler(res);
  }

  tcp::socket socket_;
  int data_len;
  char data_[max_length];
  bool is_request_parsed;
  std::string uri;
  std::string header_field;
  std::unordered_map<std::string, std::string> headers;

  boost::asio::streambuf in_buffer;
  boost::asio::streambuf out_buffer;
  http_parser parser;
  http_parser_settings settings;
  std::function<void(std::shared_ptr<response>)> handler;
  uint64_t session_id;

private:
  std::unique_ptr<base_data> data;
};

template <class T> class server {
public:
  server(boost::asio::io_context &io_context, unsigned short port,
         std::function<void(std::shared_ptr<response>)> _handler)
      : handler(_handler),
        acceptor_(io_context, tcp::endpoint(tcp::v4(), port)) {
    session_cnt = 1;
    HTTP_LOG_INFO("session_cnt: %" PRIu64 " \n", session_cnt);
    do_accept();
  }

private:
  void do_accept() {
    acceptor_.async_accept([this](boost::system::error_code ec,
                                  tcp::socket socket) {
      if (!ec) {
        HTTP_LOG_INFO("New session is created with id: %" PRIu64 "\n",
                      session_cnt);
        std::make_shared<T>(std::move(socket), handler, session_cnt++)->start();
      }
      do_accept();
    });
  }

  tcp::acceptor acceptor_;
  std::function<void(std::shared_ptr<response>)> handler;
  uint64_t session_cnt;
};

static auto
make_server(unsigned short port,
            std::function<void(std::shared_ptr<response>)> _handler) {
  return server<session>{io_context::ioc, port, _handler};
}

static void
start_server(unsigned short port,
             std::function<void(std::shared_ptr<response>)> _handler) {
  auto server_ = make_server(port, _handler);
  io_context::ioc.run();
}

// route

class route {

public:
  route() {
    handle_not_found = [](std::shared_ptr<response> res) {
      res->result() = http::status_code::not_found;
      res->end();
    };
  }

  void operator()(std::shared_ptr<response> res) {
    http::method method_ = res->reqwest().get_method();
    std::string uri = res->reqwest().get_uri_path();
    if (method_ == http::method::option and handle_option) // handle option
      handle_option(res);
    if (auto handler = route_map[std::tuple<method, std::string>{method_, uri}];
        handler and
        method_ != http::method::option) { // handle get, post, put, del (other
                                           // than option)
      res->set_header("Access-Control-Allow-Origin",
                      res->reqwest().get_header("origin"));
      handler(res);
    } else
      handle_not_found(res);
  }

  void get(std::string path,
           std::function<void(std::shared_ptr<response>)> _func) {
    route_map.emplace(std::tuple<method, std::string>(method::get, path),
                      _func);
  }

  void post(std::string path,
            std::function<void(std::shared_ptr<response>)> _func) {
    route_map.emplace(std::tuple<method, std::string>(method::post, path),
                      _func);
  }

  void
  set_option_handler(std::function<void(std::shared_ptr<response>)> _func) {
    handle_option = _func;
  }

  void
  set_not_found_handler(std::function<void(std::shared_ptr<response>)> func_) {
    handle_not_found = func_;
  }

private:
  std::function<void(std::shared_ptr<response>)> handle_option;
  std::unordered_map<std::tuple<method, std::string>,
                     std::function<void(std::shared_ptr<response>)>>
      route_map;
  std::function<void(std::shared_ptr<response>)> handle_not_found;
};

} // namespace http
