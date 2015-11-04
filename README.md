SSL双向认证lib

依赖boost/openssl

参考: http://blog.csdn.net/aalbertini/article/details/38300757

本工程为简单创建异步ssl-server/异步ssl-client而作

使用方式:

1. make
2. 生成libhyc_ssl_network.so.
3. 导出(1)头文件/(2)libhyc_ssl_network.so.
3. 模仿(3)hyc_ssl_server_test.cpp(4)hyc_ssl_client_test.cpp写2个带main函数的工程分别用作服务端客户端.
4. 证书文件自行生成,保存在指定位置.
5. 将(1)(2)(3)一起编译成服务端. 将(1)(2)(4)编译成服务端.
