#/bin/bash

# Check the sanity of the build tree with the running kernel. You need to run
# this as root.
inbox_rvt_ko="/lib/modules/`uname -r`/kernel/drivers/infiniband/sw/rdmavt/rdmavt.ko.xz"
inbox_hfi_ko="/lib/modules/`uname -r`/kernel/drivers/infiniband/hw/hfi1/hfi1.ko.xz"

if [[ $HOSTNAME == "awfm"* ]]; then
	echo "Do not run this on awfm. It is meant to be run on a build server"
	exit 1
fi

if [[ $EUID -ne 0 ]]; then
	echo "This must be run as root."
	exit 1
fi

grep rhel /etc/os-release > /dev/null
if [[ $? -ne 0 ]]; then
	echo "Currently this script only supports RedHat, you get to fix it now"
	exit 1
fi

echo "First stopping the FM if it's running"
systemctl stop opafm

echo "Unloading drivers that are currently running..."
rmmod hfi1 2>&1 > /dev/null
rmmod rdmavt 2>&1 > /dev/null

echo "Loading rdmavt..."
insmod drivers/infiniband/sw/rdmavt/rdmavt.ko
if [[ $? -ne 0 ]]; then
	echo "Could not load rdmavt"
	exit 1
fi

echo "Loading hfi1..."
insmod drivers/infiniband/hw/hfi1/hfi1.ko
if [[ $? -ne 0 ]]; then
	echo "Could not load hfi1"
	exit 1
fi

build_rvt_src=`modinfo drivers/infiniband/sw/rdmavt/rdmavt.ko | awk '/srcversion/ {print $2}'`
build_hfi_src=`modinfo drivers/infiniband/hw/hfi1/hfi1.ko | awk '/srcversion/ {print $2}'`

curr_rvt_src=`cat /sys/module/rdmavt/srcversion`
curr_hfi_src=`cat /sys/module/hfi1/srcversion`

echo ""
echo "Curr rdmavt src=$curr_rvt_src"
echo "Curr   hfi1 src=$curr_hfi_src"
echo ""
echo "Build rdmavt src=$build_rvt_src"
echo "Build   hfi1 src=$build_hfi_src"
echo ""
if [[ $build_rvt_src != $curr_rvt_src ]]; then
	echo "Build != Running RVT"
	exit 1
fi

if [[ $build_hfi_src != $curr_hfi_src ]]; then
	echo "Build != Running HFI"
	exit 1
fi

echo "Starting FM"
systemctl start opafm

echo "Waiting 10 seconds for FM to get started and links to go ACTIVE"
sleep 10
opainfo
