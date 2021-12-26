
CC = gcc
FLAGS = -Wall -g

all: task

task: task2.1.o
	$(CC) $(FLAGS) -o task task2.1.o -lpcap

task2.1.o: task2.1.c 
	$(CC) $(FLAGS) -c task2.1.c

clean:
	rm -f *.o *.a task

