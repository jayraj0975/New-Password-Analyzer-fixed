CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic -Werror
INCLUDES  = -Iinclude
LIB       = src/password_analyzer.cpp

password_analyzer: src/main.cpp $(LIB) include/password_analyzer.hpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ src/main.cpp $(LIB)

test_analyzer: tests/test_analyzer.cpp $(LIB) include/password_analyzer.hpp
	$(CXX) $(CXXFLAGS) -fsanitize=address,undefined $(INCLUDES) -o $@ tests/test_analyzer.cpp $(LIB)

.PHONY: test clean
test: test_analyzer
	./test_analyzer

clean:
	rm -f password_analyzer test_analyzer
