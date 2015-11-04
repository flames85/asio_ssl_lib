#ifndef _HYC_SSL_CLIENT_
#define _HYC_SSL_CLIENT_
#include <cstdlib>
#include <iostream>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

enum { max_length = 1024 };

typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket;

class HYCSSLClient
{
public:
    explicit HYCSSLClient(const boost::asio::ip::address &addr,
                          int port,
                          const std::string &ca_verify_file_path,
                          const std::string &local_certificate_file_path,
                          const std::string &local_private_file_path);

    void WriteMessage(const char *data, size_t bytes_transferred);

    std::size_t Run();

protected:

    virtual bool Connected(const std::string &verifyInfo) = 0;

    virtual bool ReadReady(const char* data, size_t len) = 0;

    virtual void HasWrote() = 0;

    virtual void SessionClosed(const std::string &errorMsg) = 0;

private:

    bool verify_certificate(bool preverified,
                            boost::asio::ssl::verify_context& ctx);

    void handle_connect(const boost::system::error_code& error);

    void handle_handshake(const boost::system::error_code& error);

    // 写完
    void handle_write(const boost::system::error_code& error,
                      size_t bytes_transferred);

    // 读完
    void handle_read(const boost::system::error_code& error,
                    size_t bytes_transferred);

private:


    char                                                     m_reply[max_length];
    std::string                                              m_verifyInfo;

    boost::asio::io_service                                  *m_ioservice;
    boost::asio::ssl::context                                 m_context;
    ssl_socket                                               *m_socket;
};

#endif // _HYC_SSL_CLIENT_




