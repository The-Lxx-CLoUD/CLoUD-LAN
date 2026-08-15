CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Iinclude
LDFLAGS = -lpcap -lpthread

SRC = src/main.cpp src/scanner.cpp src/packet_manager.cpp src/monitor.cpp src/common.cpp
OBJ = $(SRC:.cpp=.o)
TARGET = CLoUD-LAN

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(OBJ) -o $(TARGET) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean
