%{!?kver: %global kver %(uname -r)}
%define kdir /lib/modules/%{kver}/build
%define kernel_version %{kver}

Name:           RPMNAME
Group:		System Environment/Kernel
Summary:        Extra kernel modules for IFS
Version:        %(echo %{kver}|sed -e 's/-/_/g')
Release:        RPMRELEASE
License:        GPLv2
Source0:        %{name}-RPMVERSION.tgz
Source1:        %{name}.files
Source2:        %{name}.conf
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires:  %kernel_module_package_buildreqs

%global __os_install_post %{nil}
%define debug_package %{nil}

%define arch %(uname -p)
Requires:	kernel = %(echo %{kver} | sed -e 's/\(.*\)\.%{arch}/\1/g')

%kernel_module_package -f %{SOURCE1} default

# find our target version
%global kbuild %(
if [ -z "$kbuild" ]; then 
	echo "/lib/modules/%{kver}/build"
else 
	echo "$kbuild"
fi
)

%global kver %(
if [ -f "%{kbuild}/include/config/kernel.release" ]; then
	cat %{kbuild}/include/config/kernel.release
else
	echo "fail"
fi
)

%if 0%{?rhel} > 7
%undefine _find_debuginfo_dwz_opts
%endif

%define modlist MODLIST
%define mversion MVERSION
%define kmod_moddir %kernel_module_package_moddir

%description
Updated kernel modules for OPA IFS

%package devel
Summary: Development headers for Cornelis HFI1 driver interface
Group: System Environment/Development

%description devel
Development header files for Cornelis HFI1 driver interface

%prep
%setup -qn %{name}-RPMVERSION
for flavor in %flavors_to_build; do
	for mod in %modlist; do
		rm -rf "$mod"_$flavor
		cp -r $mod  "$mod"_$flavor
	done
done

%build
if [ "%kver" = "fail" ]; then
        if [ -z "%kbuild" ]; then
                echo "The default target kernel, %kver, is not installed" >&2
                echo "To build, set \$kbuild to your target kernel build directory" >&2
        else
                echo "Cannot find kernel version in %kbuild" >&2
        fi
        exit 1
fi
echo "Kernel version is %kver"
echo "Kernel source directory is \"%kbuild\""
# Build

for flavor in %flavors_to_build; do
	for mod in %modlist; do
		rm -rf $mod
		cp -r "$mod"_$flavor $mod
		done
	echo rpm kernel_source %{kernel_source $flavor}
	if [ -z "%mversion" ]; then
		make -j 10 CONFIG_INFINIBAND_RDMAVT=m KDIR=%{kernel_source $flavor} CONFIG_HFI_NVIDIA CONFIG_HFI_AMD M=$PWD
	else
		make -j 10  MVERSION=\"%mversion\" CONFIG_HFI_NVIDIA CONFIG_HFI_AMD CONFIG_INFINIBAND_RDMAVT=m KDIR=%{kernel_source $flavor} M=$PWD
	fi
	for mod in %modlist; do
		rm -rf "$mod"_$flavor
		mv -f $mod "$mod"_$flavor
		ln -s "$mod"_$flavor $mod
        done
done

%install
install -m 644 -D %{SOURCE2} $RPM_BUILD_ROOT/etc/depmod.d/%{name}.conf
for flavor in %flavors_to_build ; do
	flv=$( [[ $flavor = default ]] || echo ".$flavor" )
	mkdir -p $RPM_BUILD_ROOT/lib/modules/%kver$flv/%kmod_moddir/%{name}
	for mod in %modlist; do
		if [[ -x "$KERNEL_SIGNING_SCRIPT" ]]; then
			$KERNEL_SIGNING_SCRIPT "$mod"_$flavor/"$mod".ko
			/usr/sbin/modinfo "$mod"_$flavor/"$mod".ko | grep -i signer
		fi
		install -m 644 -t $RPM_BUILD_ROOT/lib/modules/%kver$flv/%kmod_moddir/%{name} "$mod"_$flavor/"$mod".ko
	done
done
(targetdir=$RPM_BUILD_ROOT%{_includedir}/uapi/rdma/hfi/
 mkdir -p $targetdir
 rsrcdir=$(pwd)/include/uapi/rdma
 srcdir=$(pwd)/include/rdma/hfi/
 cd %kdir
 sh ./scripts/headers_install.sh $targetdir $srcdir hfi1_user.h hfi1_ioctl.h
 targetdir=$RPM_BUILD_ROOT%{_includedir}/uapi/rdma/
 sh ./scripts/headers_install.sh $targetdir $rsrcdir rdma_user_ioctl.h
 sh ./scripts/headers_install.sh $targetdir $rsrcdir rdma_user_ioctl_cmds.h)

%files devel
%defattr(-,root,root,-)
%dir %{_includedir}/uapi/rdma
%dir %{_includedir}/uapi/rdma/hfi
%{_includedir}/uapi/rdma/hfi/hfi1_user.h
%{_includedir}/uapi/rdma/hfi/hfi1_ioctl.h
%{_includedir}/uapi/rdma/rdma_user_ioctl.h
%{_includedir}/uapi/rdma/rdma_user_ioctl_cmds.h


%changelog
* Mon Jan 23 2023 Greg Kresge <greg.kresge@cornelisnetworks.com>
- Update internal build scripts for distro-specific repo branches
