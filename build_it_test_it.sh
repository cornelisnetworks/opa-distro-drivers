#!/bin/bash

# This is meant to be run from a host running the matching branch that is
# checked out.

# Usage <script> [nobuild] [nvidia] [test|notest]

build_arg=
test_arg=
use_nvidia=
build_arg=
test_arg=

while [[ $# -gt 0 ]] ; do
	case $1 in
	nobuild) build_arg=$1 ;;
	nvidia) use_nvidia=y ;;
	test|notest) test_arg=$1 ;;
	*)
		echo "Unrecognized argument \"$1\"" >&2
		echo "Usage: $0 [nobuild] [nvidia] [test|notest]" >&2
		exit 2
		;;
	esac
	shift
done

sdir=$PWD
tmpdir="/tmp/tmpbuild"

if [[ $build_arg != "nobuild" ]]; then
	rm -rf $tmpdir
	gpuarg=""

	if [[ $use_nvidia = y ]] ; then
		gpuarg="-G"
	fi

	echo "GPU build arguments are \"$gpuarg\""

	./do-update-makerpm.sh -S ${PWD} -w $tmpdir $gpuarg
	if [[ $? -ne 0 ]]; then
		echo "do-update-make-rpm failed!"
		exit 1
	fi

	cd $tmpdir/rpmbuild && rpmbuild --rebuild --define "_topdir $(pwd)" --nodeps SRPMS/*.src.rpm
	if [[ $? -ne 0 ]]; then
		echo Build failed!
		exit 1
	fi

	cd $sdir
elif [[ $build_arg == "nobuild" ]]; then
	echo "Skipping build due to build_arg set to nobuild"
else
	echo "Invalid build arg."
	exit 1
fi

if [[ $test_arg == "test" ]]; then
	echo "Running Test"

	# SLES Names RPMS as follows:
	#ifs-kernel-updates-devel-5.14.21_150500.53_default-29.x86_64.rpm
	#ifs-kernel-updates-kmp-default-5.14.21_150500.53_default_k5.14.21_150500.53-29.x86_64.rpm

	#RHEL Names RPMS as follows:
	#/tmp/tmpbuild/rpmbuild/RPMS/x86_64/ifs-kernel-updates-devel-5.14.0_162.6.1.el9_1.x86_64-47.x86_64.rpm
	#/tmp/tmpbuild/rpmbuild/RPMS/x86_64/kmod-ifs-kernel-updates-5.14.0_162.6.1.el9_1.x86_64-47.x86_64.rpm

	source /etc/os-release
	if [[ $ID == "rhel" ]]; then
		rpmname=`ls $tmpdir/rpmbuild/RPMS/x86_64/kmod-ifs-kernel-updates*.rpm`
		echo "Using RHEL RPM: $rpmname"
	else #assume sles
		rpmname=`ls $tmpdir/rpmbuild/RPMS/x86_64/ifs-kernel-updates-kmp-default*.rpm`
		echo "Using SLES RPM: $rpmname"
	fi

	cd $tmpdir/rpmbuild/RPMS/x86_64
	echo "RPM Contents:"
	rpm -qpl *.rpm
	rpm2cpio $rpmname | cpio -idmv --no-absolute-filenames
	echo "Checking Srcversions:"
	echo "HFI (current):"
	cat /sys/module/hfi1/srcversion
	echo "RDMAVT (current):"
	cat /sys/module/rdmavt/srcversion

	echo "HFI from build:"
	modinfo lib/modules/`uname -r`/extra/ifs-kernel-updates/hfi1.ko | grep srcversion | awk '{print $2}' > hfi1.srcversion
	cat hfi1.srcversion

	if [[ $use_nvidia = y ]]; then
		echo "Checking GPU support:"
		modinfo lib/modules/`uname -r`/extra/ifs-kernel-updates/hfi1.ko | grep -i nvidia
		if [[ $? -eq 0 ]]; then
			echo "GPU biuld detected"
		else
			echo "Did not find GPU enabled driver"
			exit 1
		fi
	fi

	echo "RDMAVT from build:"
	modinfo lib/modules/`uname -r`/extra/ifs-kernel-updates/rdmavt.ko | grep srcversion | awk '{print $2}' > rdmavt.srcversion
	cat rdmavt.srcversion

	echo "Removing drivers"
	sudo systemctl stop opafm
	sudo rmmod hfi1
	sudo rmmod rdmavt

	echo "Checking if drivers are there"
	lsmod | grep hfi
	if [[ $? -eq 0 ]]; then
		echo "Failed to unload hfi"
		exit 1
	fi

	lsmod | grep rdmavt
	if [[ $? -eq 0 ]]; then
		echo "Failed to unload rdmavt"
		exit 1
	fi

	echo "Time to load..."
	sudo insmod lib/modules/`uname -r`/extra/ifs-kernel-updates/rdmavt.ko
	sudo insmod lib/modules/`uname -r`/extra/ifs-kernel-updates/hfi1.ko

	echo "Checking Srcversions:"
	echo "HFI (current):"
	hfi_curr_version=`cat /sys/module/hfi1/srcversion`
	echo $hfi_curr_version
	echo "RDMAVT (current):"
	rvt_curr_version=`cat /sys/module/rdmavt/srcversion`
	echo $rvt_curr_version

	sudo systemctl start opafm

	echo "Comparing verions..."
	hfi_build_vers=`cat hfi1.srcversion`
	rvt_build_vers=`cat rdmavt.srcversion`

	if [[ $hfi_build_vers != $hfi_curr_version ]]; then
		echo "Mismatch between HFI versions!"
		exit 1
	fi

	if [[ $rvt_build_vers != $rvt_curr_version ]]; then
		echo "Mismatch between RVT versions!"
		exit 1
	fi

	echo "Waiting 10 seconds for links to come up"
	sleep 10

	# opainfo would be good to call here but its not always installed
	# isntead just cat the end of the dmesg
	dmesg -d | tail -n 15

	# Clean up
	rm -rf lib
	rm -rf etc

	exit 0
elif [[ $test_arg == "notest" ]]; then
	echo "Skipping Test"
	exit 0
else
	echo "Invalid test option"
	exit 1
fi
