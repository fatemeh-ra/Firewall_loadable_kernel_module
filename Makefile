obj-m+=packet.o

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
	$(CC) read_config.c -o conf
clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
