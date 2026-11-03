src/prog: src/main.c
	gcc -O2 -o src/prog src/main.c

test: src/prog
	./src/prog | grep -q OK
