
CC = gcc
FLAGS = -Wall -g

all: taskA taskB taskC taskD taskE

taskA: task2.1A.o
	$(CC) $(FLAGS) -o taskA task2.1A.o -lpcap

taskB: task2.1B.o
	$(CC) $(FLAGS) -o taskB task2.1B.o -lpcap

taskC: task2.1C.o
	$(CC) $(FLAGS) -o taskC task2.1C.o -lpcap

taskD: task2.2.o
	$(CC) $(FLAGS) -o taskD task2.2.o


taskE: task2.3.o
	$(CC) $(FLAGS) -o taskE task2.3.o -lpcap


task2.1A.o: task2.1A.c 
	$(CC) $(FLAGS) -c task2.1A.c


task2.1B.o: task2.1B.c 
	$(CC) $(FLAGS) -c task2.1B.c


task2.1C.o: task2.1C.c 
	$(CC) $(FLAGS) -c task2.1C.c

task2.2.o: task2.2.c 
	$(CC) $(FLAGS) -c task2.2.c

task2.3.o: task2.3.c 
	$(CC) $(FLAGS) -c task2.3.c	

clean:
	rm -f *.o *.a taskA taskB taskC taskD taskE

