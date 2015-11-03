#ifndef _HYC_SSL_SERVER_H_
#define _HYC_SSL_SERVER_H_

#include <cstdlib>
#include <iostream>
#include <string>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include "hyc_ssl_session.h"

template <typename T>
class HYCSSLServer
{
public:
    explicit HYCSSLServer(const boost::asio::ip::address &addr,
                          unsigned short port,
                          const std::string &ca_verify_file_path,
                          const std::string &local_certificate_file_path,
                          const std::string &local_private_file_path);

    void Run();

private:

    std::string get_password() const;

    void start_accept();

    void handle_accept(HYCSSLSession* new_session,
                       const boost::system::error_code& error);

private:
    boost::asio::io_service         m_ioservice;
    boost::asio::ip::tcp::acceptor  m_acceptor;
    boost::asio::ssl::context       m_context;
};

#include "hyc_ssl_server.hpp"

#endif // _HYC_SSL_SERVER_H_
