gcc -o pcapcli proc.c http.c main.c -lpcap -Wall -Wpedantic

gcc -o gdbpcapcli proc.c http.c main.c -lpcap -Wall -Wpedantic -g