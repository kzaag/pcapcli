gcc -o pcapcli http.c main.c utils.c -lpcap -Wall -Wpedantic

gcc -o gdbpcapcli http.c main.c utils.c -lpcap -Wall -Wpedantic -g