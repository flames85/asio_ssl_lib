LIBS=-lboost_system -lboost_filesystem -lssl -lcrypto -L./lib -lpthread -ldl -lrt

CXXFLAGS = -g -Wall

CXX := g++

all: hyc_ssl_client_test hyc_ssl_server_test

# build
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $<

# link
hyc_ssl_client_test : hyc_ssl_client.o hyc_ssl_client_test.o
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $^ $(LIBS)

hyc_ssl_server_test: hyc_ssl_session.o hyc_ssl_server_test.o 
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $^ $(LIBS)

clean:
	rm -f hyc_ssl_server_test hyc_ssl_client_test *.o
