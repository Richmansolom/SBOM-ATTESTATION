CXX = g++
CXXFLAGS = -std=c++17 -O2

all: app

app: main.cpp
	$(CXX) $(CXXFLAGS) main.cpp -o app -lssl -lcrypto

clean:
	rm -f app
