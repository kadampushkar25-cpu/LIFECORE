CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra
OBJS = main.o MessageQueue.o

emergency_messenger: $(OBJS)
	$(CXX) $(CXXFLAGS) -o emergency_messenger $(OBJS) -lsodium

main.o: main.cpp MessageQueue.h Encryption.h
	$(CXX) $(CXXFLAGS) -c main.cpp

MessageQueue.o: MessageQueue.cpp MessageQueue.h Encryption.h
	$(CXX) $(CXXFLAGS) -c MessageQueue.cpp

clean:
	rm -f *.o emergency_messenger
