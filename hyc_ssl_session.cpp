#include "hyc_ssl_session.h"

HYCSSLSession::HYCSSLSession()
{
}

void HYCSSLSession::Init(boost::asio::io_service& io_service,
                             boost::asio::ssl::context& context)
{
    m_socket = new ssl_socket(io_service, context);
}


void HYCSSLSession::Start()
{
    // 开始验证客户端(单向验证可省略)
    m_socket->set_verify_mode(boost::asio::ssl::verify_peer);
    m_socket->set_verify_callback(boost::bind(&HYCSSLSession::handle_verify_certificate, this, _1, _2));

    // 开始握手, 握手完成则开始读写tcp数据
    m_socket->async_handshake(boost::asio::ssl::stream_base::server,
                             boost::bind(&HYCSSLSession::handle_handshake,
                                         this,
                                         boost::asio::placeholders::error));
}

ssl_socket::lowest_layer_type& HYCSSLSession::Socket()
{
    return m_socket->lowest_layer();
}


// (单向验证可省略)
bool HYCSSLSession::handle_verify_certificate(bool preverified,
                                                  boost::asio::ssl::verify_context& ctx)
{
    // The verify callback can be used to check whether the certificate that is
    // being presented is valid for the peer. For example, RFC 2818 describes
    // the steps involved in doing this for HTTPS. Consult the OpenSSL
    // documentation for more details. Note that the callback is called once
    // for each certificate in the certificate chain, starting from the root
    // certificate authority.

    // In this example we will simply print the certificate's subject name.

    char subject_name[256];
    X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
    X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);

    std::cout << "["
              << m_socket->lowest_layer().remote_endpoint().address().to_string()
              << ":"
              << m_socket->lowest_layer().remote_endpoint().port()
              << "]"
              << " verifying:"
              << subject_name
              << std::endl;

    handle_connected();

    return preverified;
}

void HYCSSLSession::handle_handshake(const boost::system::error_code& error)
{
    if (!error)
    {
        std::cout << "["
                  << m_socket->lowest_layer().remote_endpoint().address().to_string()
                  << ":"
                  << m_socket->lowest_layer().remote_endpoint().port()
                  << "] connected"
                  << std::endl;

        // 异步读
        m_socket->async_read_some(boost::asio::buffer(m_data, max_length),
                                 boost::bind(&HYCSSLSession::handle_read,
                                             this,
                                             boost::asio::placeholders::error,
                                             boost::asio::placeholders::bytes_transferred));
    }
    else
    {
        session_error(error.message());
    }
}

// 读完
void HYCSSLSession::handle_read(const boost::system::error_code& error,
                                    size_t bytes_transferred)
{
    if (!error)
    {
        std::cout << "["
                  << m_socket->lowest_layer().remote_endpoint().address().to_string()
                  << ":"
                  << m_socket->lowest_layer().remote_endpoint().port()
                  << "]"
                  << " read:"
                  << std::string(m_data, bytes_transferred)
                  << std::endl;

        handle_readed();

        // ## 此处重要, 可能希望handle_readed来返回需要写回的内容

        // 异步写
        boost::asio::async_write(*m_socket,
                                 boost::asio::buffer(m_data, bytes_transferred),
                                 boost::bind(&HYCSSLSession::handle_write,
                                             this,
                                             boost::asio::placeholders::error));
    }
    else
    {
        session_error(error.message());
    }
}

// 写完
void HYCSSLSession::handle_write(const boost::system::error_code& error)
{
    if (!error)
    {
        handle_wrote();

        // 异步读
        m_socket->async_read_some(boost::asio::buffer(m_data, max_length),
                                 boost::bind(&HYCSSLSession::handle_read,
                                             this,
                                             boost::asio::placeholders::error,
                                             boost::asio::placeholders::bytes_transferred));
    }
    else
    {
        session_error(error.message());
    }
}

void HYCSSLSession::session_error(const std::string &error_message)
{
    std::cout << "["
              << m_socket->lowest_layer().remote_endpoint().address().to_string()
              << ":"
              << m_socket->lowest_layer().remote_endpoint().port()
              << "]"
              << " error:"
              << error_message
              << std::endl;

    handle_closed();

    delete this;
}

void HYCSSLSession::asyn_write_message(const char *data, size_t bytes_transferred)
{
    boost::asio::async_write(*m_socket,
                             boost::asio::buffer(data, bytes_transferred),
                             boost::bind(&HYCSSLSession::handle_write,
                                         this,
                                         boost::asio::placeholders::error));
}
