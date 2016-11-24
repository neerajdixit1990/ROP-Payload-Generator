vuln1: vuln1.c
	gcc -g -fno-stack-protector -mpreferred-stack-boundary=2 -o vuln1 vuln1.c
vuln2: vuln2.c
	gcc -g -fno-stack-protector -mpreferred-stack-boundary=2 -o vuln2 vuln2.c
all: vuln1 vuln2

clean:
	rm -rf vuln1 vuln2
