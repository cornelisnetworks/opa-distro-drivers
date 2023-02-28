This is the distro verion of the HFI1 and associated drivers with additional
fixes and improvements by Cornelis Networks for things that have not filtered
down into the distros yet. This is a bridge between distro and upstream
kernel.org drivers.

All changes to build and other ancillary files should probably be checked into
the master branch. This branch will then get checked out to start each distro.

To create a new distro branch, start with master. Run the extract_distro_base.sh
script. The reason to start with master is so that you can add any build
updates/fixes to master branch. Then split off the actual distro code.

Here is an example after running the extract_distro_base.sh script:

awfm-02 $ git status
On branch master
Your branch is up to date with 'origin/master'.

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        modified:   README.md
        modified:   extract_distro_base.sh

Untracked files:
  (use "git add <file>..." to include in what will be committed)
        build/
        drivers/
        include/

This shows I have modified 2 files and added build, drivers, include directories.
I would first want to commit the changes to README.md and extract_distro_base.sh.

git add README.md
git add extract_distro_base.sh
git commit

Then create a new branch.

git checkout -b new_branch
git add drivers/*
git add include/*
git commit
