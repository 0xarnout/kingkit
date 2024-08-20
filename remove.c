#include <stdio.h>
#include <string.h>


int main() {
    FILE *fptr = fopen("/etc/ld.so.preload", "r");
    if (fptr == NULL) {
        perror("fopen");
        return 1;
    }

    char library_name[500];
    if (fgets(library_name, sizeof(library_name), fptr) == NULL) {
        perror("fgets");
        return 1;
    }
    library_name[strcspn(library_name, "\n")] = '\0'; //remove the newline

    if (remove("/etc/ld.so.preload") == -1) {
        perror("remove");
        return 1;
    }
    printf("The library is %s, you can remove it with `rm -rf %s`\n", library_name, library_name);
    return 0;
}
