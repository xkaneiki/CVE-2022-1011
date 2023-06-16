all:
	gcc -static -o exp exp.c
clean:
	rm -rf exp