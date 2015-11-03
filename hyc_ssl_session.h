#ifndef _HYC_SSL_SESSION_H_
#define _HYC_SSL_SESSION_H_

#include <cstdlib>
#include <iostream>
#include <string>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>


enum { max_length = 1024 };

typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket;

class HYCSSLSession
{
public:
    explicit HYCSSLSession();

    void Init(boost::asio::io_service& io_service,
              boost::asio::ssl::context& context);

    void Start();

    ssl_socket::lowest_layer_type& Socket();

    virtual void asyn_write_message(const char *data, size_t bytes_transferred);

protected:

    virtual void handle_connected() = 0;

    virtual void handle_readed() = 0;

    virtual void handle_wrote() = 0;

    virtual void handle_closed() = 0;

private:

    // (单向验证可省略)
    bool handle_verify_certificate(bool preverified,
                                   boost::asio::ssl::verify_context& ctx);

    void handle_handshake(const boost::system::error_code& error);

    // 读完
    void handle_read(const boost::system::error_code& error,
                     size_t bytes_transferred);

    // 写完
    void handle_write(const boost::system::error_code& error);

    // 连接发生错误
    void session_error(const std::string &error_message);

private:
    ssl_socket     	*m_socket;
    char            m_data[max_length];
};

#endif // _HYC_SSL_SESSION_H_
