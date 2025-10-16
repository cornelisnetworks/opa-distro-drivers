#!/bin/bash

DEFAULT_KERNEL_VERSION=""
kerneldir="./"

pkgname="opxs-modules-dkms"
pkgbase=$pkgname

set -e

if [[ -e /etc/os-release ]]; then
	. /etc/os-release
else
	echo "File /etc/os-release is missing."
	exit 1
fi
VERSION_ID_MAJOR=${VERSION_ID%%.*}
VERSION_ID_MINOR=${VERSION_ID#*.}
if [[ $VERSION_ID_MINOR == $VERSION_ID ]]; then
	VERSION_ID_MINOR=''
fi

echo "VERSION_ID = $VERSION_ID"
echo "PRETTY_NAME = $PRETTY_NAME"
if [[ -n "$MVERSION" ]]; then
	echo "MVERSION = $MVERSION"
fi

function usage
{
	cat <<EOL
usage:
	${0##*/} -h
	${0##*/} [-G] [-A] [-w dirname]
	${0##*/} -S srcdir [-w dirname]

Options:

-S srcdir  - fetch source directly from a specified directory

-w dirname - work directory, defaults to a mktemp directory
-h         - this help text
EOL
}

srcdir=""
workdir=""
filedir=""
distro=""
kernelsrc=""
build_amd=
build_nvidia=
gpuopts=""

while getopts "S:hw:GA" opt; do
    	case "$opt" in
	S)	srcdir="$OPTARG"
		[ ! -e "$srcdir" ] && echo "srcdir $srcdir not found" && exit 1
		srcdir=$(readlink -f "$srcdir")
		;;
	h)	usage
		exit 0
		;;
	w)	workdir="$OPTARG"
		;;
	G)
		build_nvidia=y
		echo "Will build with NVIDIA GPU support"
		;;
	A)
		build_amd=y
		echo "Will build with AMD GPU support"
		;;
    	esac
done

echo "srcdir = $srcdir"

DEFAULT_KERNEL_VERSION=$(uname -r)

if [ "$DEFAULT_KERNEL_VERSION" == "" ]; then
	echo "Unable to generate the kernel version"
	exit 1
fi

if [ -d "/lib/modules/$DEFAULT_KERNEL_VERSION/build" ]; then
	kernelsrc=$(readlink /lib/modules/$DEFAULT_KERNEL_VERSION/build)
	echo "kernelsrc = $kernelsrc"
else
	echo "Unable to find kernel source /lib/modules/$DEFAULT_KERNEL_VERSION/build"
	echo "Is your kernel headers package installed?"
	exit 1
fi

if [[ $ID != "ubuntu" || $VERSION_ID != "24.04" ]]; then
	echo "Unsupported distro " ${ID}
	exit 1
fi

VERSION_MINOR=$(uname -r | cut -d '.' -f 2)
if [[ $VERSION_MINOR != "8" ]]; then
	echo "Unsupported distro kernel " ${DEFAULT_KERNEL_VERSION}
	exit 1
fi

# create final version of the variables
if [ -n "$workdir" ]; then
	mkdir -p "$workdir" || exit 1
else
	workdir=$(mktemp -d --tmpdir=$(pwd) build.XXXX)
	[ ! $? ] && exit 1
fi

pkgarch=noarch

# configure the file dir
filedir=$srcdir/files
echo "filedir = $filedir"

pkgrelease=r`git rev-list --count HEAD`
echo "pkgrelease is $pkgrelease"

if [[ $build_nvidia = y ]]; then
	gpuopts="CONFIG_HFI1_NVIDIA=y"
fi

if [[ $build_amd = y ]]; then
	amdversion=$(dpkg -l amdgpu-dkms | grep amdgpu-dkms -m 1 | cut -d : -f 2 | cut -f 1 -d ' ' | sed -e s/\.[0-9]*-/-/g)
	amdmodsyms=/var/lib/dkms/amdgpu/$amdversion/$(uname -r)/x86_64/module/Module.symvers
	if [ ! -e "$amdmodsyms" ]; then
		echo "AMD module symbols not found."
		echo "Update DKMS from https://github.com/dell/dkms to at least 3.1.8."
		echo "Then rebuild the amdgpu modules with:"
		echo "    sudo dkms build -m amdgpu -v $amdversion -k \`uname -r\` --force"
		rm -rf "$workdir"
		exit 1
	fi
	echo "AMD module symbols found at $amdmodsyms"
	gpuopts="CONFIG_HFI1_AMD=y KBUILD_EXTRA_SYMBOLS=$amdmodsyms"
fi

pkgname=$(echo "$pkgname" | sed -e 's/[.]/_/g')
if [[ $build_nvidia = y ]]; then
	pkgname+="-cuda"
fi
if [[ $build_amd = y ]]; then
	pkgname+="-rocm"
fi
devpkgname="$pkgname-dev"
pkgversion=$(echo "$DEFAULT_KERNEL_VERSION" | cut -d - -f 1)
# build final package name 
pkgfull="$pkgname-$pkgversion-$pkgrelease-noarch"
devpkgfull="$devpkgname-$pkgversion-$pkgrelease-noarch"

# after cd, where are we *really*
cd -P "$workdir"; workdir=$(pwd)
tardir=$workdir/$pkgfull/usr/src/$pkgname-$pkgversion-$pkgrelease
rm -rf $tardir
rm -rf $devtardir

mkdir -p $tardir/hfi1
mkdir -p $tardir/rdmavt
mkdir -p $tardir/include/rdma
mkdir -p $tardir/include/uapi/rdma/hfi

echo "Working in $workdir"
echo "Tardir is $tardir"

# create the Makefiles
echo "Creating Makefile ($tardir/Makefile)"

cp $filedir/Makefile.top $tardir/Makefile

echo "Creating Makefile ($tardir/rdmavt/Makefile)"
cp $filedir/Makefile.rdmavt $tardir/rdmavt/Makefile

echo "Creating Makefile ($tardir/hfi1/Makefile)"
cp $filedir/Makefile.hfi $tardir/hfi1/Makefile

echo "Creating DKMS config file"
cat $filedir/dkms.conf | sed -e "s/@@VERSION@@/$pkgversion-$pkgrelease/" \
			     -e "s!@@GPUOPTS@@!$gpuopts!"\
			     -e "s/@@PACKAGE@@/$pkgname/" > $tardir/dkms.conf

echo "SRCDIR is $srcdir"
echo "KernelDir is $kerneldir"


# We need to use the distro headers as much as possible but override these
echo "Copying Files from $srcdir to $tardir..."
cp $srcdir/drivers/infiniband/hw/hfi1/*.c $tardir/hfi1/
cp $srcdir/drivers/infiniband/hw/hfi1/*.h $tardir/hfi1/
cp $srcdir/drivers/infiniband/sw/rdmavt/*.c $tardir/rdmavt/
cp $srcdir/drivers/infiniband/sw/rdmavt/*.h $tardir/rdmavt/
cp $srcdir/include/uapi/rdma/hfi/* $tardir/include/uapi/rdma/hfi/
cp $srcdir/include/uapi/rdma/rdma_user_ioctl.h $tardir/include/uapi/rdma
cp $srcdir/include/uapi/rdma/rdma_user_ioctl_cmds.h $tardir/include/uapi/rdma
cp $srcdir/include/rdma/opa_port_info.h $tardir/include/rdma
cp $srcdir/include/rdma/rdma_vt.h $tardir/include/rdma
cp $srcdir/include/rdma/rdmavt_qp.h $tardir/include/rdma
cp $srcdir/include/rdma/tid_rdma_defs.h $tardir/include/rdma

echo "final package name is $workdir/$pkgfull"
echo "final dev package name is $workdir/$devpkgfull"

# setup deb files here
# postinst and prerm scripts will take care of moving headers around

mkdir $workdir/$pkgfull/DEBIAN

# make control file for main package
cat > $workdir/$pkgfull/DEBIAN/control << CEOF
Package: ${pkgname}
Version: ${pkgversion}-${pkgrelease}
Architecture: all
Maintainer: Dennis Dalessandro <dennis.dalessandro@cornelisnetworks.com>
Description: Kernel modules for Cornelis Omni-Path Architecture HFI drivers
CEOF
conline="Conflicts: $pkgbase-cuda, $pkgbase-rocm"
depline="Depends: linux-headers-generic (>=6.8.0-~), dkms (>=3.0.0)"
if [[ $build_nvidia = y ]]; then
nvdrvname=$(dpkg -l | grep nvidia-kernel-source | awk '{print $2}')
depline+=", $nvdrvname"
conline="Conflicts: $pkgbase, $pkgbase-rocm"
fi
if [[ $build_amd = y ]]; then
amddrvname=$(dpkg -l | grep amdgpu-dkms | awk '{print $2}' | head -n 1)
depline+=", $amddrvname"
conline="Conflicts: $pkgbase-cuda, $pkgbase"
fi
echo "${depline}" >> $workdir/$pkgfull/DEBIAN/control
echo "${conline}" >> $workdir/$pkgfull/DEBIAN/control

cat $filedir/postinst-dkms | sed -e "s/@@VERSION@@/$pkgversion-$pkgrelease/" \
       				 -e "s/@@PACKAGE@@/$pkgname/" > $workdir/$pkgfull/DEBIAN/postinst
cat $filedir/prerm-dkms | sed -e "s/@@VERSION@@/$pkgversion-$pkgrelease/" \
			      -e "s/@@PACKAGE@@/$pkgname/" > $workdir/$pkgfull/DEBIAN/prerm
chmod +x $workdir/$pkgfull/DEBIAN/postinst
chmod +x $workdir/$pkgfull/DEBIAN/prerm

echo "Control file for $pkgfull"
echo "------------"
cat $workdir/$pkgfull/DEBIAN/control
echo "------------"

# setup deb files for dev package
echo "Creating deb files for $devpkgfull"

# Install sanitized headers for user space development using the kernel's
# headers_install.sh script. This is the same method used by the RPM spec file.
(
    # The destination for the final headers in the .deb package.
    targetdir_base=$workdir/$devpkgfull/usr/include/uapi/rdma
    mkdir -p $targetdir_base/hfi

    # The location of the source headers from our build stage.
    srcdir=$tardir

    # The headers_install.sh script needs to be run from the kernel build directory.
    cd $kernelsrc

    # Install and sanitize each required header file.
    sh ./scripts/headers_install.sh $srcdir/include/uapi/rdma/rdma_user_ioctl.h $targetdir_base/rdma_user_ioctl.h
    sh ./scripts/headers_install.sh $srcdir/include/uapi/rdma/rdma_user_ioctl_cmds.h $targetdir_base/rdma_user_ioctl_cmds.h
    sh ./scripts/headers_install.sh $srcdir/include/uapi/rdma/hfi/hfi1_user.h $targetdir_base/hfi/hfi1_user.h
    sh ./scripts/headers_install.sh $srcdir/include/uapi/rdma/hfi/hfi1_ioctl.h $targetdir_base/hfi/hfi1_ioctl.h
)

# The postinst and prerm scripts are not needed for the -dev package as we are
# installing headers directly to their final location. They are part of the
# main package to manage kernel modules.
mkdir $workdir/$devpkgfull/DEBIAN

# make control file for dev package
cat > $workdir/$devpkgfull/DEBIAN/control << CEOF
Package: ${devpkgname}
Version: ${pkgversion}-${pkgrelease}
Architecture: all
Maintainer: Dennis Dalessandro <dennis.dalessandro@cornelisnetworks.com>
Description: Header files for Cornelis Omni-Path Architecture HFI drivers
Depends: ${pkgname} (= ${pkgversion}-${pkgrelease})
CEOF

echo "Control file for $devpkgfull"
echo "------------"
cat $workdir/$devpkgfull/DEBIAN/control
echo "------------"

echo "Building debs"
cp $filedir/hdr* $tardir/

echo "Building deb files"
dpkg-deb --build --root-owner-group $workdir/$pkgfull
dpkg-deb --build --root-owner-group $workdir/$devpkgfull
echo "Success"
exit 0
