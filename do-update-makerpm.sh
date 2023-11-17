#!/bin/bash

DEFAULT_KERNEL_VERSION=""
kerneldir="./"

modules_cnt=0

# Add each module separately
modules[$modules_cnt]="rdmavt"
files_to_copy[$modules_cnt]="
	drivers/infiniband/sw/rdmavt/ah.c
	drivers/infiniband/sw/rdmavt/ah.h
	drivers/infiniband/sw/rdmavt/cq.c
	drivers/infiniband/sw/rdmavt/cq.h
	drivers/infiniband/sw/rdmavt/mad.c
	drivers/infiniband/sw/rdmavt/mad.h
	drivers/infiniband/sw/rdmavt/mcast.c
	drivers/infiniband/sw/rdmavt/mcast.h
	drivers/infiniband/sw/rdmavt/mmap.c
	drivers/infiniband/sw/rdmavt/mmap.h
	drivers/infiniband/sw/rdmavt/mr.c
	drivers/infiniband/sw/rdmavt/mr.h
	drivers/infiniband/sw/rdmavt/pd.c
	drivers/infiniband/sw/rdmavt/pd.h
	drivers/infiniband/sw/rdmavt/qp.c
	drivers/infiniband/sw/rdmavt/qp.h
	drivers/infiniband/sw/rdmavt/srq.c
	drivers/infiniband/sw/rdmavt/srq.h
	drivers/infiniband/sw/rdmavt/trace.c
	drivers/infiniband/sw/rdmavt/trace.h
	drivers/infiniband/sw/rdmavt/trace_rvt.h
	drivers/infiniband/sw/rdmavt/trace_qp.h
	drivers/infiniband/sw/rdmavt/trace_tx.h
	drivers/infiniband/sw/rdmavt/trace_mr.h
	drivers/infiniband/sw/rdmavt/trace_rc.h
	drivers/infiniband/sw/rdmavt/trace_cq.h
	drivers/infiniband/sw/rdmavt/vt.c
	drivers/infiniband/sw/rdmavt/vt.h
	drivers/infiniband/sw/rdmavt/rc.c
"

((modules_cnt++))
modules[$modules_cnt]="hfi1"
files_to_copy[$modules_cnt]="
	drivers/infiniband/hw/hfi1/affinity.c
	drivers/infiniband/hw/hfi1/affinity.h
	drivers/infiniband/hw/hfi1/aspm.c
	drivers/infiniband/hw/hfi1/aspm.h
	drivers/infiniband/hw/hfi1/chip.c
	drivers/infiniband/hw/hfi1/chip.h
	drivers/infiniband/hw/hfi1/chip_registers.h
	drivers/infiniband/hw/hfi1/common.h
	drivers/infiniband/hw/hfi1/debugfs.c
	drivers/infiniband/hw/hfi1/debugfs.h
	drivers/infiniband/hw/hfi1/device.c
	drivers/infiniband/hw/hfi1/device.h
	drivers/infiniband/hw/hfi1/diag.c
	drivers/infiniband/hw/hfi1/driver.c
	drivers/infiniband/hw/hfi1/efivar.c
	drivers/infiniband/hw/hfi1/efivar.h
	drivers/infiniband/hw/hfi1/eprom.c
	drivers/infiniband/hw/hfi1/eprom.h
	drivers/infiniband/hw/hfi1/file_ops.c
	drivers/infiniband/hw/hfi1/firmware.c
	drivers/infiniband/hw/hfi1/hfi.h
	drivers/infiniband/hw/hfi1/ipoib.h
	drivers/infiniband/hw/hfi1/ipoib_main.c
	drivers/infiniband/hw/hfi1/ipoib_tx.c
	drivers/infiniband/hw/hfi1/init.c
	drivers/infiniband/hw/hfi1/intr.c
	drivers/infiniband/hw/hfi1/iowait.h
	drivers/infiniband/hw/hfi1/mad.c
	drivers/infiniband/hw/hfi1/mad.h
	drivers/infiniband/hw/hfi1/mmu_rb.c
	drivers/infiniband/hw/hfi1/mmu_rb.h
	drivers/infiniband/hw/hfi1/opa_compat.h
	drivers/infiniband/hw/hfi1/pcie.c
	drivers/infiniband/hw/hfi1/pin_amd.c
	drivers/infiniband/hw/hfi1/pin_system.c
	drivers/infiniband/hw/hfi1/pin_nvidia.c
	drivers/infiniband/hw/hfi1/pin_nvidia.h
	drivers/infiniband/hw/hfi1/pinning.c
	drivers/infiniband/hw/hfi1/pinning.h
	drivers/infiniband/hw/hfi1/pio.c
	drivers/infiniband/hw/hfi1/pio_copy.c
	drivers/infiniband/hw/hfi1/pio.h
	drivers/infiniband/hw/hfi1/platform.c
	drivers/infiniband/hw/hfi1/platform.h
	drivers/infiniband/hw/hfi1/qp.c
	drivers/infiniband/hw/hfi1/qp.h
	drivers/infiniband/hw/hfi1/qsfp.c
	drivers/infiniband/hw/hfi1/qsfp.h
	drivers/infiniband/hw/hfi1/rc.c
	drivers/infiniband/hw/hfi1/ruc.c
	drivers/infiniband/hw/hfi1/sdma.c
	drivers/infiniband/hw/hfi1/sdma.h
	drivers/infiniband/hw/hfi1/sdma_txreq.h
	drivers/infiniband/hw/hfi1/sysfs.c
	drivers/infiniband/hw/hfi1/tid_nvidia.c
	drivers/infiniband/hw/hfi1/tid_system.c
	drivers/infiniband/hw/hfi1/trace.c
	drivers/infiniband/hw/hfi1/trace.h
	drivers/infiniband/hw/hfi1/trace_ctxts.h
	drivers/infiniband/hw/hfi1/trace_dbg.h
	drivers/infiniband/hw/hfi1/trace_ibhdrs.h
	drivers/infiniband/hw/hfi1/trace_misc.h
	drivers/infiniband/hw/hfi1/trace_rc.h
	drivers/infiniband/hw/hfi1/trace_rx.h
	drivers/infiniband/hw/hfi1/trace_tx.h
	drivers/infiniband/hw/hfi1/trace_mmu.h
	drivers/infiniband/hw/hfi1/trace_nvidia.h
	drivers/infiniband/hw/hfi1/uc.c
	drivers/infiniband/hw/hfi1/ud.c
	drivers/infiniband/hw/hfi1/user_exp_rcv.c
	drivers/infiniband/hw/hfi1/user_exp_rcv.h
	drivers/infiniband/hw/hfi1/user_pages.c
	drivers/infiniband/hw/hfi1/user_sdma.c
	drivers/infiniband/hw/hfi1/user_sdma.h
	drivers/infiniband/hw/hfi1/verbs.c
	drivers/infiniband/hw/hfi1/verbs.h
	drivers/infiniband/hw/hfi1/verbs_txreq.c
	drivers/infiniband/hw/hfi1/verbs_txreq.h
	drivers/infiniband/hw/hfi1/vnic.h
	drivers/infiniband/hw/hfi1/vnic_main.c
	drivers/infiniband/hw/hfi1/vnic_sdma.c
	drivers/infiniband/hw/hfi1/exp_rcv.c
	drivers/infiniband/hw/hfi1/exp_rcv.h
	drivers/infiniband/hw/hfi1/iowait.c
	drivers/infiniband/hw/hfi1/opfn.c
	drivers/infiniband/hw/hfi1/opfn.h
	drivers/infiniband/hw/hfi1/rc.h
	drivers/infiniband/hw/hfi1/tid_rdma.c
	drivers/infiniband/hw/hfi1/tid_rdma.h
	drivers/infiniband/hw/hfi1/trace_iowait.h
	drivers/infiniband/hw/hfi1/trace_tid.h
	drivers/infiniband/hw/hfi1/fault.c
	drivers/infiniband/hw/hfi1/fault.h
	drivers/infiniband/hw/hfi1/msix.c
	drivers/infiniband/hw/hfi1/msix.h
	drivers/infiniband/hw/hfi1/netdev_rx.c
	drivers/infiniband/hw/hfi1/ipoib_rx.c
	drivers/infiniband/hw/hfi1/netdev.h
"

include_dirs[0]="include/rdma"
include_dirs[1]="include/rdma/hfi"
include_dirs[2]="include/uapi/rdma"
include_files_to_copy[0]="
	include/rdma/rdmavt_qp.h
	include/rdma/rdmavt_mr.h
	include/rdma/rdmavt_cq.h
	include/rdma/rdma_vt.h
	include/rdma/ib_hdrs.h
    include/rdma/ib_sysfs.h
	include/rdma/opa_vnic.h
	include/rdma/opa_addr.h
	include/rdma/tid_rdma_defs.h
	include/uapi/rdma/rvt-abi.h
"
include_files_to_copy[1]="
	include/uapi/rdma/hfi/hfi1_user.h
	include/uapi/rdma/hfi/hfi1_ioctl.h
"
include_files_to_copy[2]="
	include/uapi/rdma/rdma_user_ioctl.h
	include/uapi/rdma/rdma_user_ioctl_cmds.h
"

include_dirs_cnt=${#include_dirs[@]}

# ridiculously long to encourage good names later
rpmname="ifs-kernel-updates"

set -e

if [[ -e /etc/os-release ]]; then
	. /etc/os-release
	if [[ "$ID" == "sle_hpc" ]]; then
		ID="sles"
	fi
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
distro_dir=""
build_amd=
build_nvidia=

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

if [[ $ID == "rhel" ]]; then
	distro_dir=RHEL$VERSION_ID_MAJOR$VERSION_ID_MINOR
	if [[ $VERSION_ID_MAJOR == "7" && $VERSION_ID_MINOR -ge 8 ]]; then
		distro_dir=RHEL77
		VERSION_ID="7.8"
		VERSION_ID_MINOR="8"
	fi
elif [[ $ID == "sles" ]]; then
	if [[ -z $VERSION_ID_MINOR ]]; then
		distro_dir=SLES$VERSION_ID_MAJOR
	else
		distro_dir=SLES${VERSION_ID_MAJOR}SP${VERSION_ID_MINOR}
	fi
fi

# create final version of the variables
if [ -n "$workdir" ]; then
	mkdir -p "$workdir" || exit 1
else
	workdir=$(mktemp -d --tmpdir=$(pwd) build.XXXX)
	[ ! $? ] && exit 1
fi

distro=$ID
echo "distro = $distro"

# configure the file dir
filedir=$srcdir/files

rpmrelease=`git rev-list --count HEAD`
if [[ $gpu == "yes" ]]; then
	rpmrelease+="cuda"
fi

# after cd, where are we *really*
cd -P "$workdir"; workdir=$(pwd)
tardir=$workdir/stage
rm -rf $tardir
for (( i = 0 ; i <= modules_cnt ; i++ ))
do
	mkdir -p $tardir/${modules[$i]}
done

echo "Working in $workdir"

# create the Makefiles
echo "Creating Makefile ($tardir/Makefile)"

cp $filedir/Makefile.top $tardir/Makefile

echo "Creating Makefile ($tardir/rdmavt/Makefile)"
cp $filedir/Makefile.rdmavt $tardir/rdmavt/Makefile

echo "Creating Makefile ($tardir/hfi1/Makefile)"
cp $filedir/Makefile.hfi $tardir/hfi1/Makefile

DEFAULT_KERNEL_VERSION=$(uname -r)

if [ "$DEFAULT_KERNEL_VERSION" == "" ]; then
	echo "Unable to generate the kernel version"
	exit 1
fi

echo "rpmrelease = $rpmrelease"
echo "Setting up RPM build area"
mkdir -p rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# make sure rpm component strings are clean, should be no-ops
rpmname=$(echo "$rpmname" | sed -e 's/[.]/_/g')
rpmversion=$(echo "$DEFAULT_KERNEL_VERSION" | sed -e 's/-/_/g')
rpmrequires=$(echo "$DEFAULT_KERNEL_VERSION" | sed -e 's/.[^.]*$//')

# get kernel(-devel) rpm version and release values
if [ $distro = 'rhel' ]
then
	kernel_rpmver=$(rpm -q --qf %{VERSION} kernel-$(uname -r))
	kmod_subdir=extra
else
	kernel_rpmver=$(rpm -q --qf %{VERSION} kernel-default)
	kmod_subdir=updates
fi
# create a new $rpmname.conf and $rpmname.files
src_path=$workdir/rpmbuild/SOURCES/

# prepare files list and depmod config for every module built
echo "%defattr(644,root,root,755)" > $src_path/$rpmname.files

modlist=""
for (( i = 0 ; i <= modules_cnt ; i++ ))
do
        echo "override ${modules[$i]} $kernel_rpmver-* weak-updates/${modules[$i]}" >> $src_path/$rpmname.conf
        echo "/lib/modules/%2-%1/$kmod_subdir/$rpmname/${modules[$i]}.ko" >> $src_path/$rpmname.files
	modlist+=" ${modules[$i]}"
done
echo "/etc/depmod.d/$rpmname.conf" >> $src_path/$rpmname.files

# build the tarball
echo "Copy the working files from $srcdir/$kerneldir"
echo "Copy the working files to $tardir"
pushd $srcdir/$kerneldir
for (( i = 0 ; i <= modules_cnt ; i++ ))
do
	cp ${files_to_copy[$i]} $tardir/${modules[$i]}/
done
echo "Copying header files"
for (( i = 0 ; i < include_dirs_cnt ; i++ ))
do
        mkdir -p $tardir/${include_dirs[$i]}
        cp ${include_files_to_copy[$i]} $tardir/${include_dirs[$i]}/
done
cp $srcdir/$kerneldir/LICENSE $tardir/.
popd
echo "Building tar file"
(cd $tardir; tar cfz - --transform="s,^,${rpmname}-${rpmversion}/," *) > \
	rpmbuild/SOURCES/$rpmname-$rpmversion.tgz
cd $workdir

# create the spec file
echo "Creating spec file"
cp $filedir/$rpmname.spec $workdir/rpmbuild/SPECS/$rpmname.spec

sed -i "s/RPMNAME/$rpmname/g" $workdir/rpmbuild/SPECS/$rpmname.spec
sed -i "s/RPMRELEASE/$rpmrelease/g" $workdir/rpmbuild/SPECS/$rpmname.spec
sed -i "s/RPMVERSION/$rpmversion/g" $workdir/rpmbuild/SPECS/$rpmname.spec
sed -i "s/MODLIST/$modlist/g" $workdir/rpmbuild/SPECS/$rpmname.spec

if [ $VERSION_ID = '8.0' ]; then
	sed -i "s/kernel_source/kbuild/g" $workdir/rpmbuild/SPECS/$rpmname.spec
fi
if [[ -n "$MVERSION" ]]; then
	sed -i "s/mversion MVERSION/mversion \"${MVERSION}\"/" $workdir/rpmbuild/SPECS/$rpmname.spec
else
	sed -i "/mversion MVERSION/d" $workdir/rpmbuild/SPECS/$rpmname.spec
fi

if [[ $build_nvidia = y ]]; then
	sed -i "s/CONFIG_HFI_NVIDIA/CONFIG_HFI1_NVIDIA=y/g" $workdir/rpmbuild/SPECS/$rpmname.spec
else
	sed -i "s/CONFIG_HFI_NVIDIA//g" $workdir/rpmbuild/SPECS/$rpmname.spec
fi

if [[ $build_amd = y ]] ; then
	sed -i "s/CONFIG_HFI_AMD/CONFIG_HFI1_AMD=y/g" $workdir/rpmbuild/SPECS/$rpmname.spec
else
	sed -i "s/CONFIG_HFI_AMD//g" $workdir/rpmbuild/SPECS/$rpmname.spec
fi

# moment of truth, run rpmbuild
rm -rf ksrc
echo "Building SRPM"
cd rpmbuild
rpmbuild -bs --define "_topdir $(pwd)" SPECS/${rpmname}.spec
ret=$?

rm -f drivers/infiniband/ulp/ipoib

exit $ret
