CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall
SRC = main.cpp MessageQueue.cpp
OBJ = $(SRC:.cpp=.o)
TARGET = messenger
LDLIBS = -lsodium -lcurl

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJ) $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

test: test_roundtrip
	./test_roundtrip

test_roundtrip: test_roundtrip.cpp
	$(CXX) $(CXXFLAGS) -o test_roundtrip test_roundtrip.cpp -lsodium

clean:
	rm -f $(OBJ) $(TARGET) test_roundtrip rotate_keys reencrypt_log
