#
# Build system for out-of-tree driver builds
#

# If building with the kernel build system utilize the Makefile that is present
# in the driver source directory. This Makefile is for building directly from
# the CLI outside of a kernel build system.

KDIR ?= /lib/modules/`uname -r`/build

all: rdmavt hfi1

hfi1:
	$(MAKE) -C $(KDIR) M=$$PWD/drivers/infiniband/hw/hfi1 NOSTDINC_FLAGS=-I$$PWD

rdmavt:
	$(MAKE) -C $(KDIR) M=$$PWD/drivers/infiniband/sw/rdmavt CONFIG_INFINIBAND_RDMAVT=m NOSTDINC_FLAGS=-I$$PWD

clean:
	$(MAKE) -C $(KDIR) M=$$PWD/drivers/infiniband/sw/rdmavt clean
	$(MAKE) -C $(KDIR) M=$$PWD/drivers/infiniband/hw/hfi1 clean


