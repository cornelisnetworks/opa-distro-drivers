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

distro=$1
srpm=""
gitr=""

cdir=$PWD
bdir="build"


if [[ $distro == "RHEL" ]]; then
	srpm=$2
	if [[ ! -e $srpm ]]; then
		echo "srpm file invalid"
		exit 1
	fi
	echo "Press ENTER to copy and extract $srpm to $bdir"
	read nothing

	echo "Copying $srpm to build directory"
	if [[ -d $bdir ]]; then
		echo "$bdir directory already found please remove manually"
		exit 1
	fi

	mkdir $bdir
	cp $srpm $bdir/

	echo "Extracting SRPM files..."
	cd $bdir
	fn=$(basename -- "$srpm")
	rpm2cpio $fn | cpio -idmv --no-absolute-filenames
	if [[ $? -ne 0 ]]; then
		echo "Could not extract srcrpm"
		exit 1
	fi

	echo "Uncompressing kernel source..."
	name=""
	new_name=""
	unxz linux-*.tar.xz
	if [[ $? -ne 0 ]]; then
		echo "xz failed, trying gunzip"
		tar xvzf linux.tar.gz
		if [[ $? -ne 0 ]]; then
			echo "Could not gunzip kernel"
			exit 1
		fi
		new_name="linux"
	else
		echo "Untarring kernel source..."
		tar xf linux-*.tar
		if [[ $? -ne 0 ]]; then
			echo "Could not untar kernel"
			exit 1
		fi
		str="linux-*.tar"
		name=`echo $str`
		new_name=${name%.tar}
	fi
	
	kdir=$bdir/$new_name

elif [[ $distro == "SLES" ]]; then
	gitr=$2
	cd $gitr
	echo "going to copy:"
	git describe
	kdir=$gitr
fi

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
