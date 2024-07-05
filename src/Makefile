# add more modules here!
obj-m = proc_leak.o bof_module.o
KERNEL_VERSION=5.4

all: 
	echo $(OBJECTS)
	make -C ../linux-$(KERNEL_VERSION) M=$(PWD) CFLAGS_MODULE="-fno-stack-protector" modules

clean:
	make -C ../linux-$(KERNEL_VERSION) M=$(PWD) clean
