#include "hyc_ssl_server.h"
#include "hyc_ssl_session.h"

/////////////////////////////////////////////////////////////////////////////

class HYCMySSLSession : public HYCSSLSession
{

public:

protected:
    virtual void handle_connected() {
        std::cout << "### handle_connected" << std::endl;
    }

    virtual void handle_readed()  {
        std::cout << "### handle_readed" << std::endl;
    }

    virtual void handle_wrote()  {
        std::cout << "### handle_wrote" << std::endl;
    }

    virtual void handle_closed() {
        std::cout << "### handle_closed" << std::endl;
    }
};

/////////////////////////////////////////////////////////////////////////////

int main(int argc, char* argv[])
{
    try
    {
        if (argc != 2)
        {
            std::cerr << "Usage: server <port>\n";
            return 1;
        }

        boost::asio::ip::address addr;
        addr.from_string("0.0.0.0");

        std::string ca_verify_file_path = "./certificate/ca-cert.pem";
        std::string local_certificate_file_path = "certificate/server-cert.pem";
        std::string local_private_file_path = "certificate/server-cert.key";

        HYCSSLServer<HYCMySSLSession> _server(addr,
                                              std::atoi(argv[1]),
                                              ca_verify_file_path,
                                              local_certificate_file_path,
                                              local_private_file_path);

        _server.Run();

        std::cout << "bye!" << std::endl;
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}
