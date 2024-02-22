#!/bin/bash

# This is meant to be run from a host running the matching branch that is
# checked out.

# Usage <script> [nobuild] [amd] [nvidia] [test|notest]

build_arg=
test_arg=
use_nvidia=
use_amd=
build_arg=
test_arg=

while [[ $# -gt 0 ]] ; do
	case $1 in
	nobuild) build_arg=$1 ;;
	nvidia) use_nvidia=y ;;
	amd) use_amd=y ;;
	test|notest) test_arg=$1 ;;
	*)
		echo "Unrecognized argument \"$1\"" >&2
		echo "Usage: $0 [nobuild] [nvidia] [amd] [test|notest]" >&2
		exit 2
		;;
	esac
	shift
done

if [[ -z $test_arg ]]; then
	echo "Invalid test option; you must specify test or notest"
	exit 2
fi

sdir=$PWD
tmpdir="/tmp/tmpbuild"

export MVERSION="dev-build"

if [[ $build_arg != "nobuild" ]]; then
	rm -rf $tmpdir
	gpuarg=""

	if [[ $use_nvidia = y ]] ; then
		gpuarg="-G"
	fi

	if [[ $use_amd = y ]] ; then
		gpuarg="$gpuarg -A"
	fi

	echo "GPU build arguments are \"$gpuarg\""

	./do-update-makedeb.sh -S ${PWD} -w $tmpdir $gpuarg
	if [[ $? -ne 0 ]]; then
		echo "do-update-makedeb failed!"
		exit 1
	fi

	echo "Just did do-update-makedev"

	cd $sdir
elif [[ $build_arg == "nobuild" ]]; then
	echo "Skipping build due to build_arg set to nobuild"
else
	echo "Invalid build arg."
	exit 1
fi

if [[ $test_arg == "test" ]]; then
	echo "Running Test"
	cd $tmpdir

	source /etc/os-release
	debname=` ls -t -1 *.deb | head -n 1`
	echo "Using Ubuntu DEB: $debname"

	echo "DEB Contents:"
	dpkg -c $debname
	echo "Unpacking DEB"

	ar vx $debname
	tar xvf data.tar.zst

	echo "Checking Srcversions:"
	echo "HFI (current):"
	cat /sys/module/hfi1/srcversion
	echo "RDMAVT (current):"
	cat /sys/module/rdmavt/srcversion

	echo "HFI from build:"
	modinfo lib/modules/`uname -r`/extra/opxs-kernel-updates/hfi1.ko | grep srcversion | awk '{print $2}' > hfi1.srcversion
	cat hfi1.srcversion

	if [[ $use_nvidia = y ]]; then
		echo "Checking GPU support:"
		modinfo lib/modules/`uname -r`/extra/opxs-kernel-updates/hfi1.ko | grep -i nvidia
		if [[ $? -eq 0 ]]; then
			echo "GPU biuld detected"
		else
			echo "Did not find GPU enabled driver"
			exit 1
		fi
	fi

	if [[ $use_amd = y ]] ; then
		echo "Checking AMD GPU support:"
		modinfo lib/modules/`uname -r`/extra/opxs-kernel-updates/hfi1.ko | grep -E '\<(amd_|amdgpu)'
		if [[ $? -eq 0 ]] ; then
			echo "AMD features detected"
		else
			echo "Did not find AMD features"
			exit 1
		fi
	fi

	echo "RDMAVT from build:"
	modinfo lib/modules/`uname -r`/extra/opxs-kernel-updates/rdmavt.ko | grep srcversion | awk '{print $2}' > rdmavt.srcversion
	cat rdmavt.srcversion

	echo "Removing drivers"
	sudo systemctl stop opa-fm
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
	sudo insmod lib/modules/`uname -r`/extra/opxs-kernel-updates/rdmavt.ko
	sudo insmod lib/modules/`uname -r`/extra/opxs-kernel-updates/hfi1.ko

	echo "Checking Srcversions:"
	echo "HFI (current):"
	hfi_curr_version=`cat /sys/module/hfi1/srcversion`
	echo $hfi_curr_version
	echo "RDMAVT (current):"
	rvt_curr_version=`cat /sys/module/rdmavt/srcversion`
	echo $rvt_curr_version

	sudo systemctl start opa-fm

	echo "Comparing verions..."
	hfi_build_vers=`cat hfi1.srcversion`
	rvt_build_vers=`cat rdmavt.srcversion`

	if [[ $hfi_build_vers != $hfi_curr_version ]]; then
		echo "Mismatch between HFI versions!"
		exit 1
	else
		echo "HFI versions match"
	fi

	if [[ $rvt_build_vers != $rvt_curr_version ]]; then
		echo "Mismatch between RVT versions!"
		exit 1
	else
		echo "RDMAVT versions match"
	fi

	echo "Waiting 10 seconds for links to come up"
	sleep 10

	# opainfo would be good to call here but its not always installed
	# isntead just cat the end of the dmesg
	sudo dmesg -d | tail -n 15

	rm -rf lib etc usr debian-binary *.zst *.srcversion
	exit 0
elif [[ $test_arg == "notest" ]]; then
	echo "Skipping Test"
	exit 0
else
	echo "Invalid test option"
	exit 1
fi
