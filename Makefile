all: bin

bin: main.o filter.o
	g++ -o bin main.o filter.o -lnetfilter_queue

main.o: netfilter.h main.cpp
	g++ -c -o main.o main.cpp

filter.o: netfilter.h filter.cpp
	g++ -c -o filter.o filter.cpp

