#include "hyc_ssl_client.h"

class HYCMySSLClient : public HYCSSLClient {
public:
    explicit HYCMySSLClient(const boost::asio::ip::address &addr,
                           unsigned short port,
                           const std::string &ca_verify_file_path,
                           const std::string &local_certificate_file_path,
                            const std::string &local_private_file_path)
        : HYCSSLClient(addr, port, ca_verify_file_path, local_certificate_file_path, local_private_file_path)
    {

    }

protected:

    virtual bool Connected(const std::string &verifyInfo) {
        std::cout << "["
                  << 1
                  << ":"
                  << 2
                  << "]"
                  << " verifying:"
                  << verifyInfo
                  << std::endl;

        std::cout << "Enter message: ";
        std::cin.getline(m_request, max_length);
        size_t request_length = strlen(m_request);
        WriteMessage(m_request, request_length);
        return true;
    }

    virtual bool ReadReady(const char* data, size_t len) {
        std::cout << "["
                  << 1
                  << ":"
                  << 2
                  << "]"
                  << " read:"
                  << std::string(data, len)
                  << std::endl;

        std::cout << "Enter message: ";
        std::cin.getline(m_request, max_length);
        size_t request_length = strlen(m_request);
        WriteMessage(m_request, request_length);
        return true;
    }

    virtual void HasWrote() {
        std::cout << "["
                  << 1
                  << ":"
                  << 2
                  << "]"
                  << " write ok"
                  << std::endl;
    }

    virtual void SessionClosed(const std::string &errorMsg) {
        std::cout << "["
                  << 1
                  << ":"
                  << 2
                  << "]"
                  << " close: "
                  << errorMsg
                  << std::endl;
    }

private:
    char          m_request[max_length];
};

int main(int argc, char* argv[])
{
    try
    {
        if (argc != 3)
        {
            std::cerr << "Usage: client <host> <port>\n";
            return 1;
        }

        boost::asio::ip::address addr;
        addr.from_string(argv[1]);

        std::string ca_verify_file_path = "./certificate/ca-cert.pem";
        std::string local_certificate_file_path = "certificate/client-cert.pem";
        std::string local_private_file_path = "certificate/client-cert.key";

        HYCMySSLClient client(addr,
                              std::atoi(argv[2]),
                              ca_verify_file_path,
                              local_certificate_file_path,
                              local_private_file_path);

        client.Run();

        std::cout << "out run" << std::endl;
    }
    catch (std::exception& e)
    {
        std::cerr << "[main]Exception: " << e.what() << "\n";
    }

    return 0;
}
