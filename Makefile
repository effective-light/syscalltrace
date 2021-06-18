FLAGS = -Wextra -O2 -std=gnu99 -g

sct: syscalltrace.h syscalltrace.o
	gcc ${FLAGS} -o $@ $^

%.o: %.c
	gcc ${FLAGS} -c $<

clean:
	rm -f *.o sct
