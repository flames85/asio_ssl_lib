LIBS=-lboost_system -lboost_filesystem -lssl -lcrypto -L./third -L./ -lpthread -ldl -lrt 

CXXFLAGS = -g -Wall -fPIC

CXX := g++

all: libhyc_ssl_network.a hyc_ssl_client_test hyc_ssl_server_test

# build
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< 

# build so
libhyc_ssl_network.a : hyc_ssl_client.o hyc_ssl_session.o
	ar -crs libhyc_ssl_network.a $^ 

# link
hyc_ssl_client_test : hyc_ssl_client_test.o
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $^ -lhyc_ssl_network $(LIBS)

hyc_ssl_server_test: hyc_ssl_server_test.o 
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $^ -lhyc_ssl_network $(LIBS)

clean:
	rm -f hyc_ssl_server_test hyc_ssl_client_test *.o *.so *.a
