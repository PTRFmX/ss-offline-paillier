#include <stdio.h>
#include <iostream>
#include <string>
#include "offline/arithmetic.h"

using namespace std;

void printHelp() {
    printf("help\n");
}

int main(int argc, char** argv) {
    if (argc != 6) {
        printHelp();
        exit(1);
    }
    int n = stoi(argv[1]), d = stoi(argv[2]), active = stoi(argv[3]), port = stoi(argv[5]);
    string addr = argv[4];
    ArithmeticOffline ao(n, d, active, addr, port);
    ao.generateMTs();
}