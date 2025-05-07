#include <algorithm>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <vector>

#include "io_base.hpp"

namespace beast     = boost::beast;
namespace websocket = beast::websocket;
namespace net       = boost::asio;
using tcp           = boost::asio::ip::tcp;

namespace ws {
//-----------------------------------------------------------------------------

void fail(beast::error_code ec, char const * what)
{
    std::cerr << what << ": " << ec.message() << "\n";
}

class message
{
    class base
    {
    public:
        base() {};
        base(const base & other) = delete;

        virtual void do_write() = 0;
        virtual void do_read()  = 0;
        virtual ~base() {}
    };

    template <typename T>
    class wrapper : public base
    {
    public:
        wrapper(const wrapper & other) = delete;

        wrapper(wrapper && other) { p = other.p; }
        wrapper(std::weak_ptr<T> p_) { p = p_; }

        void do_write()
        {
            if (auto w_p = p.lock())
            {
                w_p->do_write();
            }
        }

        void do_read()
        {
            if (auto w_p = p.lock())
            {
                w_p->do_read();
            }
        }

        ~wrapper() {}

        std::weak_ptr<T> p;
    };

public:
    message()                             = delete;
    message & operator=(message & other)  = delete;
    message & operator=(message && other) = delete;

    message(message && other) : base_(other.base_), os(other.os.rdbuf())
    {
        buffer_read     = other.buffer_read;
        is_owning       = other.is_owning;
        is_sent         = other.is_sent;
        other.is_owning = false;
    }

    template <class T>
    message(std::weak_ptr<T> connect_, boost::asio::const_buffer _buffer, boost::asio::streambuf & _output_buffer) :
        buffer_read(_buffer), os(&_output_buffer)
    {
        base_     = new wrapper<T>(connect_);
        is_owning = true;
        is_sent   = false;
    }

    std::string_view data() const { return std::string_view{ (char *) buffer_read.data(), buffer_read.size() }; }

    std::ostream & data_out() { return os; }

    void send() { base_->do_write(); }

    ~message()
    {
        if (is_sent == false and is_owning)
            base_->do_read();

        if (is_owning)
            delete base_;
    }

private:
    base * base_;
    bool is_owning;
    bool is_sent;
    boost::asio::const_buffer buffer_read;
    std::ostream os;
};

// Echoes back all received WebSocket messages
class ws_session : public std::enable_shared_from_this<ws_session>
{
public:
    // Take ownership of the socket
    explicit ws_session(tcp::socket && socket, std::function<void(message)> _message_handler) :
        ws_(std::move(socket)), message_handler(_message_handler)
    {
        state_ = state::none;
    }

    void run() { net::dispatch(ws_.get_executor(), beast::bind_front_handler(&ws_session::on_run, shared_from_this())); }

    void on_run()
    {
        ws_.set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));

        // Set a decorator to change the Server of the handshake
        ws_.set_option(websocket::stream_base::decorator([](websocket::response_type & res) {
            res.set(beast::http::field::server, std::string(BOOST_BEAST_VERSION_STRING) + " websocket-server-async");
        }));
        ws_.async_accept(beast::bind_front_handler(&ws_session::on_accept, shared_from_this()));
    }

    void on_accept(beast::error_code ec)
    {
        if (ec)
            return fail(ec, "accept");

        do_read();
    }

    void do_read()
    {
        if (state_ == state::writing or state_ == state::reading)
            return;
        state_ = state::reading;

        input_buffer.clear();
        ws_.async_read(input_buffer, beast::bind_front_handler(&ws_session::on_read, shared_from_this()));
    }

    void on_read(beast::error_code ec, std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);
        state_ = state::reading_completed;

        if (ec == websocket::error::closed)
            return;

        if (ec)
            return fail(ec, "read");

        ws_.text(ws_.got_text());
        output_buffer.prepare(1024 * 1024);

        message_handler(message{ std::weak_ptr<ws_session>{ shared_from_this() }, input_buffer.data(), output_buffer });
    }

    void do_write()
    {
        state_ = state::writing;
        ws_.async_write(output_buffer.data(), beast::bind_front_handler(&ws_session::on_write, shared_from_this()));
    }

    void on_write(beast::error_code ec, std::size_t bytes_transferred)
    {
        state_ = state::writing_completed;
        boost::ignore_unused(bytes_transferred);

        if (ec)
            return fail(ec, "write");

        output_buffer.consume(output_buffer.size());

        do_read();
    }

private:
    enum state
    {
        none = 0,
        reading,
        reading_completed,
        writing,
        writing_completed
    } state_;

    websocket::stream<beast::tcp_stream> ws_;
    beast::flat_buffer input_buffer;
    boost::asio::streambuf output_buffer;
    std::function<void(message)> message_handler;
};

//------------------------------------------------------------------------------

// Accepts incoming connections and launches the sessions
class server : public std::enable_shared_from_this<server>
{
    net::io_context & ioc_;
    tcp::acceptor acceptor_;

public:
    server(net::io_context & ioc, tcp::endpoint endpoint, std::function<void(ws::message)> _message_handler) :
        ioc_(ioc), acceptor_(ioc), message_handler(_message_handler)
    {
        beast::error_code ec;

        // Open the acceptor
        acceptor_.open(endpoint.protocol(), ec);
        if (ec)
        {
            fail(ec, "open");
            return;
        }

        // Allow address reuse
        acceptor_.set_option(net::socket_base::reuse_address(true), ec);
        if (ec)
        {
            fail(ec, "set_option");
            return;
        }

        // Bind to the server address
        acceptor_.bind(endpoint, ec);
        if (ec)
        {
            fail(ec, "bind");
            return;
        }

        // Start listening for connections
        acceptor_.listen(net::socket_base::max_listen_connections, ec);
        if (ec)
        {
            fail(ec, "listen");
            return;
        }
    }

    // Start accepting incoming connections
    void run() { do_accept(); }

private:
    void do_accept()
    {
        acceptor_.async_accept([this](boost::system::error_code ec, tcp::socket socket) {
            if (!ec)
            {
                std::make_shared<ws_session>(std::move(socket), message_handler)->run();
            }

            do_accept();
        });
    }

    std::function<void(ws::message)> message_handler;
};

//------------------------------------------------------------------------------

auto make_server(unsigned short port, std::function<void(ws::message)> message_handler,
                 std::function<void(beast::error_code)> on_event_cb)
{
    const boost::asio::ip::address address = boost::asio::ip::make_address("0.0.0.0");
    auto server_                           = server{ io_context::ioc, tcp::endpoint{ address, port }, message_handler };
    server_.run();
    return server_;
}

void start_server(unsigned short port, std::function<void(ws::message)> message_handler)
{
    auto server_ = make_server(port, message_handler, [](beast::error_code ec) {});
    server_.run();
    io_context::ioc.run();
}

namespace client {

struct message
{
};

//------------------------------------------------------------------------------

// Report a failure
void fail(beast::error_code ec, char const * what)
{
    std::cerr << what << ": " << ec.message() << "\n";
}

// Sends a WebSocket message and prints the response
class ws_client : public std::enable_shared_from_this<ws_client>
{
public:
    // Resolver and socket require an io_context
    explicit ws_client(net::io_context & ioc, std::function<void(std::string message)> _on_message) :
        resolver_(net::make_strand(ioc)), ws_(net::make_strand(ioc))
    {
        on_message = _on_message;
    }

    // Start the asynchronous operation
    void run(char const * host, char const * port, char const * text)
    {
        // Save these for later
        host_ = host;
        text_ = text;

        // Look up the domain name
        resolver_.async_resolve(host, port, beast::bind_front_handler(&ws_client::on_resolve, shared_from_this()));
    }

    void on_resolve(beast::error_code ec, tcp::resolver::results_type results)
    {
        if (ec)
            return fail(ec, "resolve");

        // Set the timeout for the operation
        beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));

        // Make the connection on the IP address we get from a lookup
        beast::get_lowest_layer(ws_).async_connect(results, beast::bind_front_handler(&ws_client::on_connect, shared_from_this()));
    }

    void on_connect(beast::error_code ec, tcp::resolver::results_type::endpoint_type)
    {
        if (ec)
            return fail(ec, "connect");

        // Turn off the timeout on the tcp_stream, because
        // the websocket stream has its own timeout system.
        beast::get_lowest_layer(ws_).expires_never();

        // Set suggested timeout settings for the websocket
        ws_.set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));

        // Set a decorator to change the User-Agent of the handshake
        ws_.set_option(websocket::stream_base::decorator([](websocket::request_type & req) {
            req.set(beast::http::field::user_agent, std::string(BOOST_BEAST_VERSION_STRING) + " websocket-client-async");
        }));

        // Perform the websocket handshake
        ws_.async_handshake(host_, "/", beast::bind_front_handler(&ws_client::on_handshake, shared_from_this()));
    }

    void on_handshake(beast::error_code ec)
    {
        if (ec)
            return fail(ec, "handshake");

        // Send the message
        // do_write("hello world");
    }

    void do_write(std::string message)
    {
        ws_.async_write(net::buffer(message), beast::bind_front_handler(&ws_client::on_write, shared_from_this()));
    }

    void on_write(beast::error_code ec, std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        if (ec)
            return fail(ec, "write 01");

        // Read a message into our buffer
        do_read();
    }

    void do_read() { ws_.async_read(buffer_, beast::bind_front_handler(&ws_client::on_read, shared_from_this())); }

    void on_read(beast::error_code ec, std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        if (ec)
            return fail(ec, "read");

        std::cout << beast::make_printable(buffer_.data()) << std::endl;

        on_message("aaaaa");

        // Close the WebSocket connection
        // ws_.async_close(websocket::close_code::normal, beast::bind_front_handler(&ws_client::on_close, shared_from_this()));
    }

    void on_close(beast::error_code ec)
    {
        if (ec)
            return fail(ec, "close");

        // If we get here then the connection is closed gracefully

        // The make_printable() function helps print a ConstBufferSequence
        std::cout << beast::make_printable(buffer_.data()) << std::endl;
    }

private:
    tcp::resolver resolver_;
    websocket::stream<beast::tcp_stream> ws_;
    beast::flat_buffer buffer_;
    std::string host_;
    std::string text_;
    std::function<void(std::string message)> on_message;
};

// void start_ws_client(std::string _host, std::string port)
// {

//     // The io_context is required for all I/O
//     net::io_context ioc;

//     // Launch the asynchronous operation
//     std::make_shared<ws_client>(ioc)->run(_host.c_str(), port.c_str(), "text");

//     // Run the I/O service. The call will return when
//     // the socket is closed.
//     ioc.run();
// }

std::shared_ptr<ws_client> make_client(std::string host, std::string port, std::function<void(std::string message)> on_read_)
{

    auto ws_client_ = std::make_shared<ws_client>(io_context::ioc, on_read_);
    ws_client_->run(host.c_str(), port.c_str(), "text");

    return ws_client_;
}

} // namespace client

//------------------------------------------------------------------------------

} // namespace ws
