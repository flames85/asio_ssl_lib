#include "hyc_ssl_server.h"

template <typename T>
HYCSSLServer<T>::HYCSSLServer(const boost::asio::ip::address &addr,
                              unsigned short port,
                              const std::string &ca_verify_file_path,
                              const std::string &local_certificate_file_path,
                              const std::string &local_private_file_path)
: m_ioservice(new boost::asio::io_service()),
  m_context(boost::asio::ssl::context::sslv23),
  m_acceptor(*m_ioservice, boost::asio::ip::tcp::endpoint(addr, port))
{
    m_context.set_options(boost::asio::ssl::context::default_workarounds
                         | boost::asio::ssl::context::no_sslv2
                         | boost::asio::ssl::context::single_dh_use);

    m_context.set_password_callback(boost::bind(&HYCSSLServer::get_password, this));

    // CA证书, 用于验证客户端证书(单向验证可省略)
    m_context.load_verify_file(ca_verify_file_path);
    // 服务端证书, 用于被客户端验证
    m_context.use_certificate_chain_file(local_certificate_file_path);
    // 服务端密钥, 用于服务端加密
    m_context.use_private_key_file(local_private_file_path, boost::asio::ssl::context::pem);

    start_accept();
}

template <typename T>
std::size_t HYCSSLServer<T>::Run()
{
    return m_ioservice->run();
}

template <typename T>
std::string HYCSSLServer<T>::get_password() const
{
    return "test";
}

template <typename T>
void HYCSSLServer<T>::start_accept()
{
    HYCSSLSession* new_session = new T();
    new_session->Init(*m_ioservice, m_context);
    m_acceptor.async_accept(new_session->Socket(),
                            boost::bind(&HYCSSLServer::handle_accept,
                                        this,
                                        new_session,
                                        boost::asio::placeholders::error));
}

template <typename T>
void HYCSSLServer<T>::handle_accept(HYCSSLSession* new_session,
                                 const boost::system::error_code& error)
{
    if (!error)
    {
        new_session->Start();
    }
    else
    {
        delete new_session;
    }

    start_accept();
}
