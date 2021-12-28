
CC = gcc
FLAGS = -Wall -g

all: taskA taskB taskC

taskA: task2.1A.o
	$(CC) $(FLAGS) -o taskA task2.1A.o -lpcap

taskB: task2.1B.o
	$(CC) $(FLAGS) -o taskB task2.1B.o -lpcap

taskC: task2.1C.o
	$(CC) $(FLAGS) -o taskC task2.1C.o -lpcap


task2.1A.o: task2.1A.c 
	$(CC) $(FLAGS) -c task2.1A.c


task2.1B.o: task2.1B.c 
	$(CC) $(FLAGS) -c task2.1B.c


task2.1C.o: task2.1C.c 
	$(CC) $(FLAGS) -c task2.1C.c

clean:
	rm -f *.o *.a taskA taskB taskC

