#
# Build system for out-of-tree driver builds
#

# If building with the kernel build system utilize the Makefile that is present
# in the driver source directory. This Makefile is for building directly from
# the CLI outside of a kernel build system.


ifneq ($(KERNELRELEASE),)

CFLAGS_MODULE += -DUSE_PI_LED_ENABLE=1 -DIFS_DISTRO -I${M}/include
obj-y := rdmavt/ hfi1/

else

#normal makefile
KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD/drivers/infiniband/sw/rdmavt
	$(MAKE) -C $(KDIR) M=$$PWD/drivers/infiniband/hw/hfi1

rdmavt:
	$(MAKE) -C $(KDIR) M=$$PWD/drivers/infiniband/sw/rdmavt

hfi1:
	$(MAKE) -C $(KDIR) M=$$PWD/drivers/infiniband/hw/hfi1

clean:
	$(MAKE) -C $(KDIR) M=$$PWD/drivers/infiniband/sw/rdmavt clean
	$(MAKE) -C $(KDIR) M=$$PWD/drivers/infiniband/hw/hfi1 clean

dist:
	./do-update-makerpm.sh -S ${PWD} -w ${PWD}/tmp && cd tmp/rpmbuild  && rpmbuild --rebuild --define "_topdir ${PWD}/tmp" --nodeps SRPMS/*.src.rpm

endif
