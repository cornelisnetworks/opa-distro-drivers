#!/bin/bash

DEFAULT_KERNEL_VERSION=""
kerneldir="./"

# ridiculously long to encourage good names later
rpmname="opxs-kernel-updates"

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
if [[ $build_nvidia = y ]]; then
	rpmrelease+="cuda"
fi

# after cd, where are we *really*
cd -P "$workdir"; workdir=$(pwd)
tardir=$workdir/stage
rm -rf $tardir
mkdir -p $tardir/hfi1
mkdir -p $tardir/rdmavt
mkdir -p $tardir/include/rdma
mkdir -p $tardir/include/uapi/rdma/hfi

echo "Working in $workdir"

# create the Makefiles
echo "Creating Makefile ($tardir/Makefile)"

cp $filedir/Makefile.top $tardir/Makefile

echo "Creating Makefile ($tardir/rdmavt/Makefile)"
cp $filedir/Makefile.rdmavt $tardir/rdmavt/Makefile

echo "Creating Makefile ($tardir/hfi1/Makefile)"
cp $filedir/Makefile.hfi $tardir/hfi1/Makefile

echo "Creating Symlink for spec files"
rm -f $filedir/opxs-kernel-updates.spec
ln -s $filedir/opxs-kernel-updates.spec.$distro $filedir/opxs-kernel-updates.spec

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

modlist="rdmavt hfi1"
echo "override rdmavt $kernel_rpmver-* weak-updates/rdmavt" >> $src_path/$rpmname.conf
echo "/lib/modules/%2-%1/$kmod_subdir/$rpmname/rdmavt.ko" >> $src_path/$rpmname.files
echo "override hfi1 $kernel_rpmver-* weak-updates/hfi1" >> $src_path/$rpmname.conf
echo "/lib/modules/%2-%1/$kmod_subdir/$rpmname/hfi1.ko" >> $src_path/$rpmname.files

echo "/etc/depmod.d/$rpmname.conf" >> $src_path/$rpmname.files

# build the tarball
echo "Copy the working files from $srcdir/$kerneldir"
echo "Copy the working files to $tardir"

pushd $srcdir/$kerneldir

echo "Copying Files to tardir..."
cp drivers/infiniband/hw/hfi1/*.c $tardir/hfi1/
cp drivers/infiniband/hw/hfi1/*.h $tardir/hfi1/
cp drivers/infiniband/sw/rdmavt/*.c $tardir/rdmavt/
cp drivers/infiniband/sw/rdmavt/*.h $tardir/rdmavt/
cp -r include $tardir/
#cp  nclude/rdma/rdma_vt.h $tardir/include/rdma/
#cp include/rdma/rdmavt_*.h $tardir/include/rdma/
#cp include/uapi/rdma/rvt-abi.h $tardir/include/uapi/rdma/
#cp include/uapi/rdma/hfi/*.h $tardir/include/uapi/rdma/hfi/

cp $srcdir/$kerneldir/LICENSE $tardir/.
popd
echo "Building tar file"
(cd $tardir; tar cfz - --transform="s,^,${rpmname}-${rpmversion}/," *) > \
	rpmbuild/SOURCES/$rpmname-$rpmversion.tgz
cd $workdir


echo "Tarball: $rpmbuild/SOURCES/$rpmname-$rpmversion.tgz"

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

rm -f $filedir/opxs-kernel-updates.spec

exit $ret
