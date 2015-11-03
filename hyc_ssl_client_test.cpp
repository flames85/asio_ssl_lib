#include "hyc_ssl_client.h"

int main(int argc, char* argv[])
{
    try
    {
        if (argc != 3)
        {
            std::cerr << "Usage: client <host> <port>\n";
            return 1;
        }

        boost::asio::io_service io_service;

        boost::asio::ip::tcp::resolver resolver(io_service);
        boost::asio::ip::tcp::resolver::query query(argv[1], argv[2]);
        boost::asio::ip::tcp::resolver::iterator iterator = resolver.resolve(query);

        boost::asio::ssl::context ctx(boost::asio::ssl::context::sslv23);

        // CA证书, 用于验证服务端证书
        ctx.load_verify_file("./certificate/ca-cert.pem");
        // 客户端证书, 用于被服务端验证(单向验证可省略)
        ctx.use_certificate_chain_file("certificate/client-cert.pem");
        // 客户端密钥, 用于客户端加密(单向验证可省略)
        ctx.use_private_key_file("certificate/client-cert.key", boost::asio::ssl::context::pem);

        client c(io_service, ctx, iterator);

        io_service.run();

        std::cout << "out run" << std::endl;
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}
