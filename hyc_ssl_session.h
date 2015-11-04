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

    // write
    void WriteMessage(const char *data, size_t bytes_transferred);


    void Init(boost::asio::io_service& io_service,
              boost::asio::ssl::context& context);

    ssl_socket::lowest_layer_type& Socket();
    void Start();

protected:

    virtual bool NewConnection(const std::string &peerAddr,
                               int peerPort,
                               const std::string &subjectName) = 0;

    virtual bool ReadReady(const char* data, size_t len) = 0;

    virtual void HasWrote() = 0;

    virtual void SessionClosed(const std::string &errorMsg) = 0;

private:

    // (单向验证可省略)
    bool handle_verify_certificate(bool preverified,
                                   boost::asio::ssl::verify_context& ctx);

    void handle_handshake(const boost::system::error_code& error);

    // 读完
    void handle_read(const boost::system::error_code& error,
                     size_t bytes_transferred);

    // 写完
    void handle_write(const boost::system::error_code& error,
                      size_t bytes_transferred);

    // 连接发生错误
    void session_error(const std::string &error_message);

private:
    ssl_socket     	*m_socket;
    char            m_data[max_length];
    std::string     m_verifyInfo;
};

#endif // _HYC_SSL_SESSION_H_
