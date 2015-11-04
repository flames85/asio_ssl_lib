#include "hyc_ssl_server.h"
#include "hyc_ssl_session.h"

/////////////////////////////////////////////////////////////////////////////

class HYCMySSLSession : public HYCSSLSession
{
public:

protected:
    virtual bool NewConnection(const std::string &peerAddr,
                               int peerPort,
                               const std::string &subjectName)
    {
        std::cout << "["
                  << peerAddr
                  << ":"
                  << peerPort
                  << "]"
                  << " verifying:"
                  << subjectName
                  << std::endl;

        m_peerAddr = peerAddr;
        m_peerPort = peerPort;

        return true;
    }

    virtual bool ReadReady(const char* data, size_t len)  {
        std::cout << "["
                  << m_peerAddr
                  << ":"
                  << m_peerPort
                  << "]"
                  << " read:"
                  << std::string(data, len)
                  << std::endl;


        // 这里写逻辑, 然后返回
        WriteMessage("123456789", 9);

        return true;

    }

    virtual void HasWrote()  {
        std::cout << "["
                  << m_peerAddr
                  << ":"
                  << m_peerPort
                  << "]"
                  << " write ok"
                  << std::endl;
    }

    virtual void SessionClosed(const std::string &errorMsg) {
        std::cout << "["
                  << m_peerAddr
                  << ":"
                  << m_peerPort
                  << "]"
                  << " close: "
                  << errorMsg
                  << std::endl;
    }

private:
    char         m_buf[max_length];
    std::string  m_peerAddr;
    int          m_peerPort;
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
        std::cerr << "[main]Exception: " << e.what() << "\n";
    }

    return 0;
}
