CONFIG_MODULE_SIG=n

TARGET = monitoring
CURRENT = $(shell uname -r)
KDIR = /lib/modules/$(CURRENT)/build
PWD = $(shell pwd)

obj-m := $(TARGET).o
monitoring-y := md.o hooks.o list.o

default: 
	make -C $(KDIR) M=$(PWD) modules 
clean: 
	@rm -f *.o .*.cmd .*.flags *.mod.c *.order *.mod *.ko *.symvers 
	@rm -f .*.*.cmd *~ *.*~ TODO.* .*.d
	@rm -fR .tmp* 
	@rm -rf .tmp_versions 
disclean: clean 
	@rm *.ko *.symversS
load:
	sudo insmod $(TARGET).ko
unload:
	sudo rmmod $(TARGET).ko
reload: 
	sudo rmmod $(TARGET).ko
	sudo insmod $(TARGET).ko
info:
	modinfo $(TARGET).ko
logs:
	sudo dmesg
cleanlogs:
	sudo dmesg -C	
