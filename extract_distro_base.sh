#!/bin/bash

# Extract files from a  Linux kernel source tree and place them into the appropraite
# directories for out of tree builds.

# Copy the Rdmavt and Hfi1 drivers
# Also copy the header files. More than likely we won't want to change these but
# it is possible we just have to be careful about not breaking compatibility
# with existing kernel drivers in the RDMA stack as we do not want to modify
# ANYTHING other than hfi1 and rdmavt.

# Note about qib: At thist time we are not including the qib driver anymore.
# Users of qib are advised to run the Truescale package or upstream kernel.org
# kernel.

srpm=$1
cdir=$PWD

if [[ ! -e $srpm ]]; then
	echo "srpm file invalid"
	exit 1
fi

pdir="$(dirname "$srpm")"
echo "Press ENTER to extract $srpm to $pdir"
read nothing

echo "Extracting SRPM files..."
cd $pdir
rpm2cpio $srpm | cpio -idmv --no-absolute-filenames
if [[ $? -ne 0 ]]; then
	echo "Could not extract srcrpm"
	exit 1
fi

echo "Uncompressing kernel source..."
unxz linux-*.tar.xz
if [[ $? -ne 0 ]]; then
	echo "Could not unxz kernel"
	exit 1
fi

echo "Untarring kernel source..."
tar xf linux-*.tar
if [[ $? -ne 0 ]]; then
	echo "Could not untar kernel"
	exit 1
fi

str="linux-*.tar"
name=`echo $str`
new_name=${name%.tar}

kdir=$pdir/$new_name

# Back to previous directory
cd $cdir

echo "Going to extract from $kdir"

if [[ -d drivers ]]; then
	echo "Existing checkout of driver files detected."
	exit 1
fi

if [[ -d include ]]; then
	echo "Existing checkout of include files detected."
	exit 1
fi

mkdir -p drivers/infiniband/hw/hfi1
mkdir -p drivers/infiniband/sw/rdmavt
mkdir -p include/rdma
mkdir -p include/uapi/rdma/hfi

cp -r $kdir/drivers/infiniband/hw/hfi1/* drivers/infiniband/hw/hfi1/
cp -r $kdir/drivers/infiniband/sw/rdmavt/* drivers/infiniband/sw/rdmavt/
cp -r $kdir/include/rdma/* include/rdma/
cp -r $kdir/include/uapi/rdma/* include/uapi/rdma/

cd include/uapi/rdma

rm cxgb4-abi.h bnxt_re-abi.h efa-abi.h hns-abi.h mlx* mthca-abi.h ocrdma-abi.h qedr-abi.h siw-abi.h vmw_pvrdma-abi.h irdma-abi.h rdma_user_rxe.h

echo "Copy Complete. Do a test build and sanity check of the driver."
