#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
//#include <unistd.h>

int main()
{
    int mode, n, k;
    char b[101], c[101];
    FILE* f;
    f = fopen("config.txt", "r");
    fgets(b, 100, f);

    sscanf(b,"%d %d", &n, &mode);
    printf("mode:%d\n",mode);

    int fd = open("/dev/packet4", O_RDWR);
    if (fd < 0){
        perror("Failed to open the device...");
        return errno;
    }
    int ret = write(fd, b, strlen(b));
    if (ret < 0){
        perror("Failed to write the message to the device.");
        return errno;
    }
    while(fgets(b, 100, f)) {
        printf("sending data : %s", b);
        int ret = write(fd, b, strlen(b));
        if (ret < 0){
            perror("Failed to write the message to the device.");
            return errno;
        }
    }
}
