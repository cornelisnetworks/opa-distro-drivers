This is the distro verion of the HFI1 and associated drivers with additional
fixes and improvements by Cornelis Networks for things that have not filtered
down into the distros yet. This is a bridge between distro and upstream
kernel.org drivers.

All changes to build and other ancillary files should probably be checked into
the master branch. This branch will then get checked out to start each distro.

To create a new distro branch: 

1. start with checking out  master as something reflecting the distro.
	git checkout -b rhel8.7 origin/master

2. Run the extract_distro_base.sh script.
	The reason to start with master is so that you can add any build
	updates/fixes to master branch. Then split off the actual distro
	code.

	2a: SLES needs a patch to disable CONFIG_FAULT_INJECTION get it from a
	previous SLES branch. It will be obvious which to cherry pick.

3. Make it build.

	-----------
	SLES PreReq
	-----------
	The SLES kernel install does not have the unifdef binary compiled like
	it doe son RHEL. The utility is available for install but the
	headers_install tool wants a local directory version. Thus you MUST as
	root build unifdef. This is not going to be done by the script because
	having a script required to be run as root and make changes is just a
	bad idea.
	As root:
		cd /lib/modules/`uname -r`/source/scripts
		gcc -o unifdef unifdef.c

	
	Add any necessary changes to be able to build the equivalent of
	the distro driver.

	Make sure to cherry pick these changes back to the master branch!

4. Clean out temp build files
	We do not want .o files check in!

5. Add the include and drivers directories
	git add drivers/*
	git add include/*
	git commit

6. We now have an equivalent distro driver that builds. Time for "value add":
	* patches charry picked from upstream that are needed but not in distro
	* late breaking fixes
	* Non-upstremable stuff. Get from previos distro branch:
		* snoop/capture: "hfi1: Snoop/Capture"
		* Nvidia GPU: "TBD"

