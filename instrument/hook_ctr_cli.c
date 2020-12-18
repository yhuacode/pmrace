#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "hook_ctrl.h"

void print_usage() {
    printf("usage: ./hook_ctr_cli {init|free}\n");
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        print_usage();
        exit(1);
    }

    if (strncmp(argv[1], "init", 4) == 0) {
        int r = init_shared_coverage_info();
        if (r == -1) {
            perror("init error!\n");
            exit(1);
        } else {
            printf("init success, shmid = %d\n", r);
        }
        
    }
    else if (strncmp(argv[1], "free", 4) == 0) {
        int r = free_shared_coverage_info();
        if (r == -1) {
            perror("free error!\n");
            exit(1);
        } else {
            printf("free success\n");
        }
    }

    return 0;
}