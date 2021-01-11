FLAGS = -Wextra -O2 -std=gnu99 -g

ctrace: ctrace.o
	gcc ${FLAGS} -o $@ $^

%.o: %.c
	gcc ${FLAGS} -c $<

clean:
	rm -f *.o ctrace
