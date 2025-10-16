#!/bin/bash

# This is meant to be run from a host running the matching branch that is
# checked out.

# Usage <script> [nobuild] [amd] [nvidia] [test|notest]
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
build_arg=
test_arg=
use_nvidia=
use_amd=
build_arg=
test_arg=
basename=opxs-modules-dkms

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
		basename+="-cuda"
	elif [[ $use_amd = y ]] ; then
		gpuarg="-A"
		basename+="-rocm"
	fi

	echo "GPU build arguments are \"$gpuarg\""

	./do-makedkms.sh -S ${PWD} -w $tmpdir $gpuarg
	if [[ $? -ne 0 ]]; then
		echo "do-makekdms failed!"
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
	cd $tmpdir

	source /etc/os-release
	debname=` ls -t -1 *.deb | grep -v dev`
	echo "Using Ubuntu DEB: $debname"

	echo "DEB Contents:"
	dpkg -c $debname

	echo "Removing drivers"
	sudo systemctl stop opa-fm
	sudo rmmod hfi1
	sudo rmmod rdmavt

	echo "Checking if drivers are there"
	lsmod | grep hfi > /dev/null
	if [[ $? -eq 0 ]]; then
		echo "Failed to unload hfi"
		exit 1
	fi

	lsmod | grep rdmavt > /dev/null
	if [[ $? -eq 0 ]]; then
		echo "Failed to unload rdmavt"
		exit 1
	fi
	echo -e "\n-------------------"
	echo "Builtin versions:"
	h_old=`modinfo hfi1 | grep srcversion | awk '{print $2}'`
	echo "$h_old"
	r_old=`modinfo rdmavt | grep srcversion | awk '{print $2}'`
	echo "$r_old"


	echo -e "\n--------------------"
	echo "Installing deb"
	sudo dpkg -i $debname
	es=$?
	if [[ $es -ne 0 ]]; then
		echo -e "${RED}Failed to install package, status $es ${NC}"
		sudo dpkg -r $basename
		exit 1
	else
		echo -e "${GREEN}Package installed cleanly.${NC}"
	fi

	echo -e "\n--------------------"
	echo "Versions from build:"
	h_new=`modinfo hfi1 | grep srcversion | awk '{print $2}'`
	echo "$h_new"
	r_new=`modinfo rdmavt | grep srcversion | awk '{print $2}'`
	echo "$r_new"

	echo -e "\n--------------------"
	echo "Comparing verions..."
	if [[ $h_new == $h_old ]]; then
		echo -e "${RED}New HFI did not install!${NC}"
		sudo dpkg -r $basename
		exit 1
	else
		echo -e "${GREEN}HFI version update confirmed${NC}"
		echo "Original: $h_old"
		echo "Updated:  $h_new"
	fi

	if [[ $r_new == $r_old ]]; then
		echo -e "${RED}New RDMAVT did not install!${NC}"
		sudo dpkg -r $basename
		exit 1
	else
		echo -e "${GREEN}RDMAVT version update confirmed${NC}"
		echo "Original: $r_old"
		echo "Updated:  $r_new"
	fi

	if [[ $use_nvidia = y ]]; then
		echo "Checking GPU support:"
		modinfo hfi1.ko | grep -i nvidia > /dev/null
		if [[ $? -eq 0 ]]; then
			echo -e "${GREEN}Nvidia GPU build detected${NC}"
		else
			echo -e "${RED}Did not find GPU enabled driver${NC}"
			exit 1
		fi
	fi

	if [[ $use_amd = y ]] ; then
		echo "Checking AMD GPU support:"
		modinfo hfi1 | grep -E '\<(amd_|amdgpu)' > /dev/null
		if [[ $? -eq 0 ]] ; then
			echo -e "${GREEN}AMD features detected${NC}"
		else
			echo -e "${RED}Did not find AMD features${NC}"
			exit 1
		fi
	fi

	echo -e "\n--------------------"
	echo "Time to load..."
	sudo modprobe rdmavt
	sudo modprobe hfi1

	echo "Checking if drivers are there"
	lsmod | grep hfi > /dev/null
	if [[ $? -ne 0 ]]; then
		echo -e "${RED}Failed to load hfi!${NC}"
		exit 1
	else
		echo -e "${GREEN}Module hfi1 loaded${NC}"
	fi

	lsmod | grep rdmavt > /dev/null
	if [[ $? -ne 0 ]]; then
		echo -e "${RED}Failed to load rdmavt!${NC}"
		exit 1
	else
		echo -e "${GREEN}Module rdmavt loaded${NC}"
	fi

	sudo systemctl start opa-fm

	echo "Waiting 10 seconds for links to come up"
	sleep 10

	# opainfo would be good to call here but its not always installed
	# isntead just cat the end of the dmesg
	sudo dmesg -d | tail -n 15

	echo -e "\n--------------\n"
	echo "Restoring original modules"
	sudo dpkg -r $basename
	rm -rf lib etc usr debian-binary *.zst *.srcversion
	echo -e "${GREEN}Package testing successful.${NC}"
	exit 0
elif [[ $test_arg == "notest" ]]; then
	echo "Skipping Test"
	exit 0
else
	echo "Invalid test option"
	exit 1
fi
