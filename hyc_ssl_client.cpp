#include "hyc_ssl_client.h"

HYCSSLClient::HYCSSLClient(const boost::asio::ip::address &addr,
                           unsigned short port,
                           const std::string &ca_verify_file_path,
                           const std::string &local_certificate_file_path,
                           const std::string &local_private_file_path)
: m_ioservice(new boost::asio::io_service()),
  m_context(boost::asio::ssl::context::sslv23)
{
    // CA证书, 用于验证服务端证书
    m_context.load_verify_file(ca_verify_file_path);
    // 客户端证书, 用于被服务端验证(单向验证可省略)
    m_context.use_certificate_chain_file(local_certificate_file_path);
    // 客户端密钥, 用于客户端加密(单向验证可省略)
    m_context.use_private_key_file(local_private_file_path, boost::asio::ssl::context::pem);

    // new socket
    m_socket = new ssl_socket(*m_ioservice, m_context);

    // 1.开始验证服务端
    m_socket->set_verify_mode(boost::asio::ssl::verify_peer);
    m_socket->set_verify_callback(boost::bind(&HYCSSLClient::verify_certificate, this, _1, _2));

    // 2. 开始握手, 握手完成则开始读写tcp数据
    boost::asio::ip::tcp::endpoint endpoint(addr, port);
    m_socket->lowest_layer().async_connect(endpoint,
                                           boost::bind(&HYCSSLClient::handle_connect,
                                                       this,
                                                       boost::asio::placeholders::error));
}

std::size_t HYCSSLClient::Run() {
    return m_ioservice->run();
}

// 3. 验证成功
bool HYCSSLClient::verify_certificate(bool preverified,
        boost::asio::ssl::verify_context& ctx)
{
    // The verify callback can be used to check whether the certificate that is
    // being presented is valid for the peer. For example, RFC 2818 describes
    // the steps involved in doing this for HTTPS. Consult the OpenSSL
    // documentation for more details. Note that the callback is called once
    // for each certificate in the certificate chain, starting from the root
    // certificate authority.

    // In this example we will simply print the certificate's subject name.
    if(!preverified) return false;

    char subject_name[256];
    X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
    X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);

    m_verifyInfo += subject_name;
    m_verifyInfo += "\n";
    return true;
}

// 4. 连接成功
void HYCSSLClient::handle_connect(const boost::system::error_code& error)
{
    if (!error)
    {
        m_socket->async_handshake(boost::asio::ssl::stream_base::client,
                                 boost::bind(&HYCSSLClient::handle_handshake,
                                             this,
                                             boost::asio::placeholders::error));
    }
    else
    {
        SessionClosed(error.message());
    }
}

// 5. 握手成功
void HYCSSLClient::handle_handshake(const boost::system::error_code& error)
{
    if (!error)
    {
        if(!Connected(m_verifyInfo))
        {
            try
            {
                 m_socket->lowest_layer().close();
            } catch (std::exception& e) {
                std::cerr << "[HYCSSLClient::handle_handshake]Exception: " << e.what() << std::endl;
            }
        }
    }
    else
    {
        SessionClosed(error.message());
    }
}

// 写完
void HYCSSLClient::handle_write(const boost::system::error_code& error,
                                size_t bytes_transferred)
{
    if (!error)
    {
        HasWrote();

        // 异步读
        m_socket->async_read_some(boost::asio::buffer(m_reply, max_length),
                                 boost::bind(&HYCSSLClient::handle_read,
                                              this,
                                              _1,
                                              _2));
    }
    else
    {
        SessionClosed(error.message());
    }
}

// 读完
void HYCSSLClient::handle_read(const boost::system::error_code& error,
                               size_t bytes_transferred)
{
    if (!error)
    {
        if(ReadReady(m_reply, bytes_transferred))
        {
            try
            {
                 m_socket->lowest_layer().close();
            } catch (std::exception& e) {
                std::cerr << "[HYCSSLClient::handle_handshake]Exception: " << e.what() << std::endl;
            }
        }
    }
    else
    {
        SessionClosed(error.message());
    }
}

void HYCSSLClient::WriteMessage(const char *data, size_t bytes_transferred)
{
    boost::asio::async_write(*m_socket,
                             boost::asio::buffer(data, bytes_transferred),
                             boost::bind(&HYCSSLClient::handle_write,
                                         this,
                                         _1,
                                         _2));
}
