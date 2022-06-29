CFLAGS=-I/usr/src/linux-headers-4.9.253-tegra-ubuntu18.04_aarch64/nvidia/include/uapi/misc

SRC = main.c
OBJ = $(SRC:%.c=%.o)

tegra-crypt-ssk: $(OBJ)
	$(CC) -o $@ $^ -static

%.o:%.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -rf $(OBJ) tegra-crypt-ssk
