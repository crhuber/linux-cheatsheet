Linux Admin Guide
=================
** Guide to administering Linux **


## Table Of Contents

- [Linux Admin Guide](#linux-admin-guide)
  - [Table Of Contents](#table-of-contents)
  - [Age](#age)
  - [Apache](#apache)
  - [Asdf](#asdf)
  - [Bash](#bash)
  - [Boot](#boot)
  - [Command Line](#command-line)
  - [Cron](#cron)
  - [Dig](#dig)
  - [Hardware](#hardware)
  - [File System](#file-system)
  - [Fish](#fish)
  - [Firewall](#firewall)
  - [FFMpeg](#ffmpeg)
  - [Git](#git)
  - [Gpg](#gpg)
  - [IPFS](#ipfs)
  - [Jq](#jq)
  - [Memcache](#memcache)
  - [Mitmproxy](#mitmproxy)
  - [Mise](#mise)
  - [MySQL](#mysql)
  - [Networking](#networking)
  - [Netcat](#netcat)
  - [Ollama](#ollama)
  - [PHP](#php)
  - [Performance](#performance)
  - [Python](#python)
  - [Sshuttle](#sshuttle)
  - [Regex](#regex)
  - [Screen](#screen)
  - [SSH](#ssh)
  - [SSL](#ssl)
  - [SQL](#sql)
  - [SELINUX](#selinux)
  - [Terraform](#terraform)
  - [User Admin](#user-admin)
  - [VIM](#vim)
  - [YUM](#yum)

## Boot
---

* 6 Levels to booting
    - BIOS
    - MBR
    - GRUB
    - Kernel
    - Init
    - Runlevel

* BIOS
    - Searches, loads, and executes the boot loader program.
    - It looks for boot loader in floppy, cd-rom, or hard drive. You can press a key (typically F12 of F2, but it depends on your system) during the BIOS startup to change the boot sequence.
    - Once the boot loader program is detected and loaded into the memory, BIOS gives the control to it.
    - So, in simple terms BIOS loads and executes the MBR boot loader.

* MBR
    - It is located in the 1st sector of the bootable disk. Typically /dev/hda, or /dev/sda
    - MBR is less than 512 bytes in size. This has three components 1) primary boot loader info in 1st 446 bytes 2) partition table info in next 64 bytes 3) mbr validation check in last 2 bytes.
    - It contains information about GRUB (or LILO in old systems).
    - So, in simple terms MBR loads and executes the GRUB boot loader.

* GRUB

```

        If you have multiple kernel images installed on your system, you can choose which one to be executed.
        GRUB displays a splash screen, waits for few seconds, if you don’t enter anything, it loads the default kernel image as specified in the grub configuration file.
        GRUB has the knowledge of the filesystem (the older Linux loader LILO didn’t understand filesystem).
        Grub configuration file is /boot/grub/grub.conf (/etc/grub.conf is a link to this). The following is sample grub.conf of CentOS.

        boot=/dev/sda
        default=0
        timeout=5
        splashimage=(hd0,0)/boot/grub/splash.xpm.gz
        hiddenmenu
        title CentOS (2.6.18-194.el5PAE)
        root (hd0,0)
        kernel /boot/vmlinuz-2.6.18-194.el5PAE ro root=LABEL=/
        initrd /boot/initrd-2.6.18-194.el5PAE.img</strong></span>
        As you notice from the above info, it contains kernel and initrd image.
        So, in simple terms GRUB just loads and executes Kernel and initrd images.

```

* Kernel


    * Mounts the root file system as specified in the “root=” in grub.conf
    * Kernel executes the /sbin/init program
    * Since init was the 1st program to be executed by Linux Kernel, it has the process id (PID) of 1. Do a ‘ps -ef | grep init’ and check the pid.
    * initrd stands for Initial RAM Disk.
    * initrd is used by kernel as temporary root file system until kernel is booted and the real root file system is mounted. It also contains necessary drivers compiled inside, which helps it to access the hard drive partitions, and other hardware.

* Init

```
    Looks at the /etc/inittab file to decide the Linux run level.
    Following are the available run levels
    0 – halt
    1 – Single user mode
    2 – Multiuser, without NFS
    3 – Full multiuser mode
    4 – unused
    5 – X11
    6 – reboot
    Init identifies the default initlevel from /etc/inittab and uses that to load all appropriate program.
    Execute ‘grep initdefault /etc/inittab’ on your system to identify the default run level
    If you want to get into trouble, you can set the default run level to 0 or 6. Since you know what 0 and 6 means, probably you might not do that.
    Typically you would set the default run level to either 3 or 5.
```
* Runlevel

```
    Depending on your default init level setting, the system will execute the programs from one of the following directories.
    Run level 0 – /etc/rc.d/rc0.d/
    Run level 1 – /etc/rc.d/rc1.d/
    Run level 2 – /etc/rc.d/rc2.d/
    Run level 3 – /etc/rc.d/rc3.d/
    Run level 4 – /etc/rc.d/rc4.d/
    Run level 5 – /etc/rc.d/rc5.d/
    Run level 6 – /etc/rc.d/rc6.d/
    Please note that there are also symbolic links available for these directory under /etc directly. So, /etc/rc0.d is linked to /etc/rc.d/rc0.d.
    Under the /etc/rc.d/rc*.d/ directories, you would see programs that start with S and K.
    Programs starts with S are used during startup. S for startup.
    Programs starts with K are used during shutdown. K for kill.
    There are numbers right next to S and K in the program names. Those are the sequence number in which the programs should be started or killed.
    For example, S12syslog is to start the syslog deamon, which has the sequence number of 12. S80sendmail is to start the sendmail daemon, which has the sequence number of 80. So, syslog program will be started before sendmail.
```

* Shutdown the system after 10 minutes.

```
shutdown -h +10
```
* Process States

    Init process is the first process when linux boots up

            pidof systemd
            >1
    There are 4 states for a process

            - Running: running or waiting to be assigned to CPU
            - Waiting: : iowait - waiting for io, or just waiting for an event to occur. uninterruptible are ones waiting on hardware
            - Zombie: process is dead but its still in process table

    Background Jobs

             & or ctrl+z

    Foreground Jobs

            jobs
            fg %1

* Signals

    Signals notify an process of an event. Similar to how a hardware sends kernel interupts. Programs only recognize signals if they are programmed to do so.

    Shows all available signals

        kill -l

    Signal Types:

        SIGINT - interupprt
        SIGHUP - when controlling terminal is closed without closing. The OS sends sighup
        SIGINIT2 - sent when user hits control+c
        SIGQUIT - sent when quit signal Ctrl + D
        SIGKIll9 - terminates immediately and without out cleaning up
        SIGTERM15 - kill uses this by default. Clean shutdown.
        SIGTSTP2- - Control z

* System Calls

When a program does open, fork, read, write its doing a system call. Its how a program enters the kernel. it instructs the kernel to do something on its behalf. Why doesn’t the user application run itself? Because of ring levels. Users are ring3, kernel is ring0.

Userspace and Kernel space
Processes in user space only have access to small part of memory. Kernel has all. Cannot do io or have a hardware access.  Access to kernel space by system calls.
Sends an interupt to kernel if it wasn’t to write a file. Rings are so programs dont interfere with eachother


## User Admin

* Become system administrator:

```
sudo -s
sudo su
```

The accounts capable of using sudo
are specified in /etc/sudoers, which is edited with the visudo utility. By default, relevant logs are written to /var/log/secure.

* Switch user

```
su - user2
```
argument "-" Provides an environment similar to what the user would expect had the user logged in directly.

* Password file syntax

```
/etc/passwd
```

    ![alt text](passwdfile.jpg "Passwords")


    * Username: It is used when user logs in. It should be between 1 and 32 characters in length.
    * Password: An x character indicates that encrypted password is stored in /etc/shadow file.
    * User ID (UID): Each user must be assigned a user ID (UID). UID 0 (zero) is reserved for root and UIDs 1-99 are reserved for other predefined accounts. Further UID 100-999 are reserved by system for administrative and system accounts/groups.
    * Group ID (GID): The primary group ID (stored in /etc/group file)
    * User ID Info: The comment field. It allow you to add extra information about the users such as user's full name, phone number etc. This field use by finger command.
    * Home directory: The absolute path to the directory the user will be in when they log in. If this directory does not exists then users directory becomes /
    * Command/shell: The absolute path of a command or shell (/bin/bash). Typically, this is a shell. Please note that it does not have to be a shell.

* System User vs Normal User

        System users will be created with no aging information in /etc/shadow, and their numeric identifiers are chosen in the SYS_UID_MIN–SYS_UID_MAX range, defined in /etc/login.defs, instead of UID_MIN–UID_MAX (and their GID counterparts for the creation of groups).On CentOS: Although useradd --system foouser creates no home directory for that user. Service accounts often don't have a "proper" login shell, i.e. they have /usr/sbin/nologin. Moreover, service accounts are typically locked, i.e. it is not possible to login (for traditional /etc/passwd and /etc/shadow this can be achieved by setting the password hash to arbitrary values such as * or x)

* Change password

```
passwd
```

* Change password expiration

```
chage

chage -E never username  (sets to never expire)
```


* Lock user password

```
usermod -L username
```

* Define default attributes for new users (UID, Password Expiriny, HomeDir)

```
nano /etc/login.defs
```

* Kill a process

        1       HUP (hang up)
        2       INT (interrupt)
        3       QUIT (quit)
        6       ABRT (abort)
        9       KILL (non-catchable, non-ignorable kill)
        Each process is supplied with a set of standard signal handlers by the operating system in order to deal with incoming signals. When no signal is explicitly included in the command, signal 15, named SIGTERM, is sent by default. If this fails, the stronger signal 9, called SIGKILL

* Kill all users processes

```
killall -u username
```

* Kill all processes by name

```
killall firefox
pkill -9 firefox
```

* Get process id

```
pgrep bash
```

* Reload process

```
sudo kill -HUP pid_of_apache
```

* Display users using file/folder

```
fuser -u file/folder
```

* Kill processes using file/folder

```
fuser -k file/folder
```

* Add User

```
add user user1
```


* Show last logged in

```
last
last Log
last reboot  # shows last reboot
```

* Show users groups

```
groups {username}
```

* Add User to Sudo

```
usermod -a -G sudo user1
```

* Change default sudo timeout (in minutes)

add to /etc/sudoers

```
Defaults    timestamp_timeout=<value>
```

* Edit Group Config

        Nano /etc/group

    ```
        cdrom:x:24:vivek,student13,raj
        Where, group_name: It is the name of group. If you run ls -l command, you will see this name printed in the group field.  Password: Generally password is not used, hence it is empty/blank. It can store encrypted password. This is useful to implement privileged groups. Group ID (GID): Each user must be assigned a group ID. You can see this number in your /etc/passwd file.  Group List: It is a list of user names of users who are members of the group. The user names, must be separated by commas.
    ```

* Variables

```
echo $PATH #shows path variable
export -p #shows all defined
export MYAPP=1 #sets variable my app to value 1
EDITOR="nano"
```

* Add path to system path

```
export PATH=$PATH:/usr/local/bin
```

* Print usernames of logged in users:

```
users
```

* Write one line to another user from your terminal:

```
talk
```

* show info on current user

```
id
```

* show all users and host where logged in from

```
who -umH
```

* To temporarily prevent logins system wide (for all users but root) use nologin. The message in nologin will be displayed (might not work with ssh pre-shared keys).

```
echo "Sorry no login now" > /etc/nologin
```


## Hardware


* Print full date and time:

```
date

```
* Print the hostname of this machine:


```
echo $HOSTNAME
```


* Print the default file permissions(subtract from 777):

```
echo $umask
```


* Print the session timeout:

```
echo $tmout
```

* Print information about current linux distro:


```
lsb_release -a
cat /etc/*-release
cat /proc/version
```

* Print linux kernel version:

```
uname -a
```

* Print information about kernel modules:

```
lsmod
```

* Configure kernel modules (never do this):

```
modprobe
```

* Look for messages from drivers:

```
dmesg
```

* View Installed packages:

```
dpkg --get-selections
```

* Print environment variables:

```
printenv
```

* List hardware connected via PCI ports:

```
lspci
```

* List hardware connected via USB ports:

```
lsusb
```

* Print hardware info stored in BIOS:

```
dmidecode
sysreport
```


* Dump captured data off of wireless card:

```
dumpcap
```

* Dump info about keyboard drivers:

```
dumpkeys
```

* Print information about ethernet

```
ethtool
```

* Make a bootable USB

```
dd if=efidisk.img of=/dev/usb (usb device name)
```

* Make a swap file

```
dd if=/dev/zero of=/opt/myswap bs=1024 count=4
mkswap /opt/myswap
swapon -a

For adding this myswap at boot time, add following in /etc/fstab file:
/opt/myswap swap swap defaults 0 0
```

* Show default kernel

```
grubby –default-kernel
```

* Modify kernel parameters

```
nano /etc/sysctl.conf
```

* Backup & Restore MBR

```
To backup: dd if=/dev/sda of=/tmp/mbr.img_backup bs=512 count=1
To restore: dd if=/tmp/mbr.img of=/dev/sda bs=512 count=1
The MBR  is a 512 byte segment on the very first sector of your hard drive composed of three parts: 1) the boot code which is 446 bytes long, 2) the partiton table which is 64 bytes long, and 3) the boot code signature which is 2 bytes long.
```

* Sync NTP time

```
sudo service ntp stop
sudo ntpdate -s time.nist.gov
sudo service ntp start
```

* Show Memory information

```
cat /proc/meminfo
```

* Show number of cores

```
lscpu
```

* Hardware Info

```
cat /proc/cpuinfo                  # CPU model
cat /proc/meminfo                  # Hardware memory
grep MemTotal /proc/meminfo        # Display the physical memory
watch -n1 'cat /proc/interrupts'   # Watch changeable interrupts continuously
free -m                            # Used and free memory (-m for MB)
cat /proc/devices                  # Configured devices
lspci -tv                          # Show PCI devices
lsusb -tv                          # Show USB devices
lshal                              # Show a list of all devices with their properties
dmidecode                          # Show DMI/SMBIOS: hw info from the BIOS
```

## File System

* Linux file system description:

http://www.tldp.org/LDP/Linux-Filesystem-Hierarchy/html/

* inodes

```
        An inode stores basic information about a regular file, directory, or other file system object
        iNode number also called as index number, it consists following attributes:

        File type (executable, block special etc)
        Permissions (read, write etc)
        Owner
        Group
        File Size
        File access, change and modification time (remember UNIX or Linux never stores file creation
        time, this is favorite question asked in UNIX/Linux sys admin job interview)
        File deletion time
        Number of links (soft/hard)
        Extended attribute such as append only or no one can delete file including root user
        (immutability)
        Access Control List (ACLs)
```

* Show inodes of files and folders

```
ls -i
stat
```
* Find where a commmand is executed from

```
which
ie: which python  > /usr/bin
```

* list directories and recurse into subdirectories

```
ls -r
```

* Find files bigger than 100m

```
find . -size +100M
```

* Find largest directories in current directory

```
du -hs */ | sort -hr | head
```

* Find files created within last 7 days

```
find . -mtime -7
```

* Find files accessed within last 7 days

```
find . -atime -7
```

* Find Disk Usage by Directory

```
du -sh /home/*

#Using the -c option with the du command will show the grand total of used space for the designated directory
```

* check for bad blocks

```
sudo badblocks -s /dev/sda
```

* Read speed test

```
sudo hdparm -tT /dev/sda
```

* Write speed test. 16KB random write operations

```
fio --directory=/media/p_iops_vol0 --name fio_test_file --direct=1 --rw=randwrite --bs=16k --size=1G --numjobs=16 --time_based --runtime=180 --group_reporting --norandommap
```

* Display mountpounts

```
lsblk
findmnt #show mountpoints
sudo fdisk -l
df -h
df -h --output=source,target
```

* Add a new EBS disk to  server

```
lsblk  #find drive which is not mounted
sudo mkfs -t ext4 /dev/xvdf #makes file system on /dev/xvdf)
    (or sudo mkfs -it xfs /dev/xvdf #makes file system on /dev/xvdf)
sudo mkdir /mnt/my-data #make a mount point
sudo mount /dev/xvdf /mnt/my-data #mount device
```

* Show Physical Volumes

```
         pvdisplay
```

* Create Volume Group

    A group of physical volumes or disks are combined together into a single storage file which is referred to as the LVM volume group.

```
        sudo vgcreate <volume-name> <device-1> <device-2> <device-3>
```

* Create Logical Volumes

```
        sudo lvcreate –name <logical-volume-name> –size <size-of-volume> <volume-group-name>
```

* Display Logical Volumes

```
        sudo lvdisplay
```

* Format Logical Volume

```
        mkfs -t ext4 /dev/<lvm-name>
```

* Zero Out all blocks for performance

```
        if=/dev/zero of=/dev/xvdf bs=1M
```

* Create Raid0

```
        mdadm --create --verbose /dev/md0 --level=stripe --raid- devices=number_of_volumes device_name1 device_name2
```

* Resize Filesystem

```
        resize2fs
```

* Raid Levels

```
        0 - Striped set without parity or Striping
        1 - Mirrored set without parity or Mirroring
        0+1 -  (increased speed) arrays are created and they are each mirrored via an overall RAID 1 (data backup) array. By definition, this configuration requires at least 4 drives.
        5 - Provides both backup and increased speed. Additionally, a RAID 5 array can continue normally operating if one of its drives fails. The performance speed of the array will be reduced until the failed drive is replaced, but no data loss would occur. This array requires a minimum of 3 drives.
        1+0 Mirrors two drives together and then creates a striped set with the pair.
```

* Mount a new file system

```
        fdisk /dev/hda1  #create new partision
        mkfs /dev/hda1  #create file system
        mount -a        # causes all filesystems mentioned in fstab to be mounted
```

* Define boot disk

```
        cat /etc/fstab
        # UUID=9246707a-30ab-47be-b78f-bb7b24a459a8 /     ext4    defaults     1 1
        # ext4= filesystem , defaults = mount on boot
```

* Copy Files from Remote Machine to Local Machine

```
        scp root@www.server.com:/root/file.sql /home/ec2-user
```

* Copy Local directory to remote machine

```
        scp -rp sourcedirectory user@dest:/path
```

* Copy Remote directory to local path

```
        scp -r user@your.server.example.com:/path/to/foo /home/user/Desktop/
```

* Copy hello.txt from local computer to remote home directory

```
         scp hello.txt awshost1:~/
```

* Copy hello.txt from local to remote home directory, renaming it foo.txt

```
        scp hello.txt awshost1:~/foo.txt
```

* Copying ~/foo.txt from the remote computer to the current local director

```
        scp awshost1:~/foo.txt .
```

* Copying ~/foo.txt from remote to local directory cc, renaming it a.b

```
        scp awshost1:~/foo.txt cc/a.b
```

* Compress a directory

```
        tar -zcvf archive-name.tar.gz directory-name
        -c = create
        -f = following is archive name
        -v = verbose
        -z = gzip
```

* To append file to archive

```
        tar rvf archive_name.tar new file.txt
```

* Encrypt a file:

```
        gpg -o [outputfilename.gpg] -c [target file]
```

* Decrypt a file:

```
        gpg -o [outputfilename] -d [target.gpg]
```

* Uncompress file

```
        unzip filename.zip
```

* Open a compressed .tgz or .tar.gz file:

```
        tar -xvf [target.tgz]
        tar -xvf —strip-components 1  # extracts without its parent folder
        tar -xvf -C  # extracts to a different directory
```

* Find Files

```
        Find . -name http*
```

* Find all files not owned by root:

```
        find . \! -user root -print
```

* Find all files not with permissions 644:

```
        find . \! -perm 644 root -print
```

* Find files matching [filename]:

```
        locate [filename]
```

* Show a file type

```
        file image.jpg
```

* Show uncommented items in config files

```
        grep -v "#" file.conf
```

* Search for a given string in all files recursively

```
        grep -r "ramesh" *
```

* View the differences between two files:

```
        diff [file 1] [file 2]
```

* Change File Permissions

```
        chmod 775 filename
        chmod o+r file.txt  # o=other +=add r=read
        7 = Read + Write + Execute
        6 = Read + Write
        5 = Read + Execute
        4 = Read
        3 = Write + Execute
        2 = Write
        1 = Execute
        0 = All access denied
        First number is for the owner, second for the group, and third for everyon
```
        http://permissions-calculator.org/

        ![alt text](permissions.jpg "Permissions")

* Permissions On Folders

```
        r: read only the names of the files in the directory
        w: create and delete of the files in the directory
        x: traverse the directory
```

* Permissions On files

```
        r: open a file for reading (e.g. with the cat command)
        w: write a file (e.g. use sed -i (inplace) on it)
        x: execute a file
        It is important to note that a script can be executed even by a user who doesn’t have the execute permission on it. Passing a python script path to the python executable will cause python to open the file for reading and then interpret it. So it is not safe to rely on the executable permission for security. This goes for php, perl, ruby, javascript, etc, etc
```

* Copy permissions of one file onto another

```
        getfacl FILE1 | setfacl –set-file=- FILE2
```

* Show permissions on all directories in a tree

```
        namei -om /var/www/iddb.com/static
```

* Remove directory

```
        rmdir directory
```

* Logs


```
auth.log				Authentication logs
boot.log				Boot logs
btmp					Invalid login attempts
cron                 	Cron logs
daemon.log        		Logs for specific services (daemons)
dmesg					Kernel boot messages
httpd/					Apache logs
kern.log				Kernel logs
mail*					Mail server logs
messages				General/all logs
mysql*					MySQL logs
secure					Security/authentication logs
syslog					All system logs
wtmp					User logins and logouts
```

* Check Logs

```
less /var/log/messages
less /var/log/secure
less /var/log/auth
```

* Check disk space

```
df -H # H is for human readable
```

* Config Files

```
/etc/login.def - default settings template for new user accounts
/etc/motd - message of the day
/etc/inittab - defines default runlevel #id:3:initdefault:
```

* System Startup Files

```
/etc/rc.d  - scripts run from this subdir
/etc/init.d - hard location for startup scripts. Linked to /etc/rc.d/rc0.d ..etc.
/etc/rc.d/rc - file responsible for starting stopping services
/etc/rc0.d  - contains files with links to /etc/init.d/.
     k05atd - kill,priority,service
     s05atd - start,priority.service
```

* To start any script

```
run /etc/init.d/smb start

# To prevent startup delete sum link
```

* To create new startup script

```
put script in /etc/init.d/myservice

/etc/rc3.d ln s ../init.d/myservice
```

* Check for systemd or sysvinit

```
pidof /sbin/init && echo "sysvinit" || echo "other"

pidof systemd && echo "systemd" || echo "other"
```

* Show Current Runlevel

```
runlevel
who -r
```

* Change default runlevel

```
nano /etc/inittab. change id:3:initdefault. to different number
```

* Change runlevel

```
init 1 (single user mode)
```

* Check file system consistency

```
Goto single user mode:
# init 1
Unmount file system:
# umount /dev/sdb1
Now run fsck command:
# fsck /dev/sdb1
```

* Check a files type

```
file <filename>
```

* Generate md5

```
md5 <filename>
```

* Generate sha256

```
openssl sha -sha256 <filename> (mac)
```

* Symbolic Links

```
┌── ln(1) link, ln -- make links
│   ┌── Create a symbolic link.
│   │                         ┌── the path to the intended symlink
│   │                         │   can use . or ~ or other relative paths
│   │                   ┌─────┴────────┐
ln -s /path/to/original /path/to/symlink
      └───────┬───────┘
              └── the path to the original file/folder
                  can use . or ~ or other relative paths
```

* Change the open files limit from 1024 to 10240 d

```
        ulimit -n 10240                    # This is only valid within the shell
```

* Login users and applications can be configured in /etc/security/limits.conf

* System wide limits

```
    sysctl -a                          # View all system limits
    sysctl fs.file-max                 # View max open files limit
    sysctl fs.file-max=102400          # Change max open files limit
    echo "1024 50000" > /proc/sys/net/ipv4/ip_local_port_range  # port range
    cat /etc/sysctl.conf
    fs.file-max=102400                   # Permanent entry in sysctl.conf
    cat /proc/sys/fs/file-nr           # How many file descriptors are in use
```

* Find opened files on a mount point with fuser

```
        fuser -m /home
```

## Performance

* Load Average

        The "number of cores = max load"
        The three numbers represent averages over progressively longer periods of time (one, five, and fifteen minute averages)
        Rule of Thumb: on a multicore system, your load should not exceed the number of cores available.
        On a dual-core CPU, I won't even think about it until load gets and stays above 1.7 or so
        Which average should I be observing? One, five, or 15 minute?, you should be looking at the five or 15-minute averages. Frankly, if your box spikes above 1.0 on the one-minute average, you're still fine. It's when the 15-minute average goes north of 1.0 and stays there that you need to snap to.
        how do I know how many cores my system has? grep 'model name' /proc/cpuinfo | wc -l


* Show running services with their ports

```
        lsof -i # monitors network connections in real time (mac/linux)
```

* Show what files a process has open

```
        lsof -p $PID
        netstat -lptu
```

* top

    ![alt text](topoutput.jpg "Top")

    uppercase M sorts by memory

    lowercase c shows full command

```

    * check i/o wait for server slowness - Represents CPU waiting for disk I/O. if it is low then you can rule out disk access. GT > 10% is high means Disk is slow
    * CPU idle. higher the number the more bandwidth available to server. Should be >25%
    * User Time - if idle time is low, you can expect this to be high. Find process taking up cpu
    *  Memory usage: don't look at the "free" memory -- it's misleading. To get the actual memory available, subtract the "cached" memory from the "used" memory. This is because Linux caches things liberally, and often the memory can be freed up when it's needed
    * Stealtime = virtual machines are competing for resources. If %st increases on all VM's, means your VM is using too much cpu. elif %st increases on just one VM = Physical is oversold
    * cpu: usertime (time spent on processor running your program). System is the time spent in operating system kernel
    * iowait: time cpu waiting for disk or network io.
    * load: is how many processes are waiting to run
        - < 0.7 = healthy (on single core machine)
        - 1.0 = system is fully used (on single core machine)
        - 1.0 on single core, 4.0 on quad core
        - broken down by one minute, 5 minutes, 15 minutes
        - lscpu: shows how many cores
    * Memory: true memory usage is memory used - swap cached
    * swap: cached: caches files in the filesystem in memory for better performance. Uses spare memory
    * SwapTotal, SwapFree. If they are equal there is no swapping going on

```

* Show open tcp sockets

```
        lsof -nPi tcp

        -n	: This option inhibits the conversion  of  network  numbers  to  host  names  for  network  files.
         Inhibiting  conversion may make lsof run faster.  It is also useful when host name lookup is not
         working properly.
        -P : This option inhibits the conversion of port numbers to port names for network files.  Inhibiting
         the  conversion  may  make lsof run a little faster.  It is also useful when port name lookup is
         not working properly.
        -i [tcp] : This  option  selects  the  listing  of  files any of whose Internet address matches the address
         specified in i.
```

* Show bandwidth usage per connection

```
        iftop
```

* Show which apps are using the connection

```
ss -p
```

* Show Ports listening with thir process id

```
        netstat -tlnp (show ports listening with their process id)

        -l, --listening : Show only listening sockets.  (These are omitted by default.)
        -n, --numeric : Show numerical addresses instead of trying to determine symbolic host, port or user names.
        -p, --program : Show the PID and name of the program to which each socket belongs.
        -t, --tcp : Show only tcp
```

* Show Ports listening - Mac only

```
        nettop
```

* Show bandwith ussage per process

```

        nethogs
```

* Show running services

```

        ps –ax
        ps –eaf
        pstree
        ps aux
        a = show processes for all users
        u = display the process's user/owner
        x = also show processes not attached to a terminal
```

* Like top, but with a better, cleaner interface:

```
        htop
```

* Stop a process from using all system resources and lagging computer:

```
        nice [process name]
        nice command is used for changing priority of the jobs.
        Syntax: nice [OPTION] [COMMAND [ARG]…]
        Range of priority goes from -20 (highest priority) to 19 (lowest).Priority is given to a job so that the most important job is executed first by the kernel and then the other least important job
```

* Show all ruby-related PIDs and processes

```

        pgrep -fl ruby
```

* Whats a process doing?

```
        strace -f -p $PID
```

* Keep running the same command over and over

```
        watch 'ps aux | grep ruby'
```

* How much memory is left

```
        free -m

        Free: memory that is currently not used for anything. It should be small since memory shouldn’t be wasted
        Available: amount available for allocation to new process. Modern operating systems go out of their way to keep as little memory free as possible. Memory that is free is actually harder to use because it has to be transitioned from free to in use. Memory that is already in use, that is, memory that is available but not free, can easily be switched to another use.
        The "buffers" and "cached" will be released by the kernal if they are needed.
```

* Are we swapping

```
        vmstat 1
```

* Top 10 memory hogs

```
        ps aux --sort=-resident|head -11
```

* Tail all queries running against mysql

```
        pt-query-digest --processlist h=localhost --print --no-report --user xxxx --password *****
```

* Check readwrite per sec on disk

```
        iostat -xnk 5
```

* How much io disk or network is getting or sending

```
        dstat
```

* Show every call a program is making

```
        strace python myprogram.py #dont run on production db
        opensnoop -p pid  #same as strace but won't slow u down
```

* Show current directory disk size

```
        du -hs
```

* What is using the IO? Is MySQL sucking up the resources? Is it your PHP processes?

```
        dstat --top-io --top-bio
```

* top 10 memory hogs

```
        ps aux --sort=-resident|head -11
```

* Tracroute but Avoid tcp blockage

```
        tcptraceroute google.com
```

* is the host oversold

```
        top, look for %st. Stealtime = virtual machines are competing for resources.
         If %st increases on all VM's, means your VM is using too much cpu.
         elif %st increases on just one VM = Physical is oversold
```

* Disk performance

```
        A sustained increase of VolumeQueueLength way above 1 on a standard EBS volume should be treated as exhausting the throughput of that EBS volume. We recommend that you target a queue length between 4 and 8 for volumes with 2,000 to 4,000 provisioned IOPS, or a queue length of 1 for every 500 IOPS provisioned for volumes with fewer than 2,000 provisioned IOPS
```

* Bandwidth available between two computers

        iperf -s

* Test if a specific TCP/IP port is open with round trip

          hping3 www.google.com -S -V -p 443
          -S Sets the SYN tcp flag

* View Services Startup

        chkconfig --list

* Runlevels

```
Red Hat as well as most of its derivatives (such as CentOS) uses runlevels like this:


ID Description
0 Halt
1 Single user
2 Full multi-user with no networking
3 Full multi-user, console logins only
4 Not used/User definable
5 Full multi-user, with display manager as well as console logins
6 Reboot
The default runlevel is set in the /etc/inittab file with the :initdefault: entry
The default run level is 5. To disable a
service, run the following command:
/sbin/chkconfig servicename off
Unless they are required, disable the following:
anacron haldaemon messagebus apmd hidd microcode_ctl autofs` hplip* pcscd avahi-daemon* isdn readahead_early bluetooth kdump readahead_later cups* kudzu rhnsd* firstboot mcstrans setroubleshoot gpm mdmonitor xfs.
Items marked with a * are network services. It is particularly important to disable these. Additionally, the following services can be safely disabled if NFS is not in use: netfs, nfslock, portmap, rpcgssd, and rpcidmapd. Some software relies on haldaemon and messagebus, so care should be taken when disabling them
```

* Auto Start Service

        chkconfig httpd on


* Restart Service

        /etc/init.d/<servicename>

        Service <servicename> restart

* Reload Service configuration

        kill -HUP 128
        This causes the program to restart and examine its configuration files.

*

## Command Line


* Xargs: Get input from a pipe and run a command for each argument. takes strings separated by whitespace and passes them into the command specficied

        ls |xargs -n 2 echo   #-n2 means how many arguments to supply at a given time

* Awk

https://www.howtogeek.com/562941/how-to-use-the-awk-command-on-linux/

    find positional parameters

            ls -la | awk '{ print $ 5}’

* Awk (continued)

```
    awk '{ print $2, $1 }' file                  # Print and inverse first two columns
    awk '{printf("%5d : %s\n", NR,$0)}' file     # Add line number left aligned
    awk '{print FNR "\t" $0}' files              # Add line number right aligned
    awk NF test.txt                              # remove blank lines (same as grep '.')
    awk 'length > 80'                            # print line longer than 80 char)
    $0											Represents the entire line of text.
    $1											Represents the first field.
    $NF											Stands for “number of fields,” and represents the last field.
```

* Awk (output field seperators)

put a / after each output

```
    date | awk 'OFS="/" {print$2,$3,$6}'
```

* Awk (begin and ends)

put a line before everything runs
```
awk 'BEGIN {print "Dennis Ritchie"} {print $0}' dennis_ritchie.txt
```

* Awk (input field seperators)

If you want awk to work with text that doesn’t use whitespace to separate fields, you have to tell it which character the text uses as the field separator. For example, the /etc/passwd file uses a colon (:) to separate fields.

```
awk -F: '{print $1,$6}' /etc/passwd
```

* Awk (patterns)

If all we’re interested in are regular user accounts, we can include a pattern with our print action to filter out all other entries. Because User ID numbers are equal to, or greater than, 1,000, we can base our filter on that information.

```
awk -F: '$3 >= 1000 {print $1,$6}' /etc/passwd
```

* Awk with an IF statement

```
k get pdb | awk '{ if ($4 == 0) print $1;}'
```

* AWK print colum if string is in the column

```
k get node | awk '$4 ~ "d" {print $1, $3, $4;}'
```

* cut

Get the second field delimited by a dot
```
cut -f2 -d "."
```

* Sed

```
    sed 's/string1/string2/g'                    # Replace string1 with string2
    sed -i 's/wroong/wrong/g' *.txt              # Replace a recurring word with g
    sed 's/\(.*\)1/\12/g'                        # Modify anystring1 to anystring2
    sed '/<p>/,/<\/p>/d' t.xhtml                 # Delete lines that start with <p>
                                                # and end with </p>
    sed '/ *#/d; /^ *$/d'                        # Remove comments and blank lines
    sed 's/[ \t]*$//'                            # Remove trailing spaces (use tab as \t)
    sed 's/^[ \t]*//;s/[ \t]*$//'                # Remove leading and trailing spaces
    sed 's/[^*]/[&]/'                            # Enclose first char with [] top->[t]op
    sed = file | sed 'N;s/\n/\t/' > file.num     # Number lines on a file
    Regular Expressions
```
    http://www.grymoire.com/Unix/Sed.html

* Tail, Sort, Head

        ps -aux | tail -n +2 | sort -rnk 4
        tail = starting from 2 lines below otp
        sort = - reverse , numeric sort, by column 4
        head = output the first 10 lines
        uniq = with -c counts how many times a string shows up in a document uniquely

* run jobs in parallel easily:

        ls *.png | parallel -j4 convert {} {.}.jpg


* Open an editor to work with long or complex command lines

        ctrl-x ctrl-e

* Wait until [command 1] is finished to execute [command 2]


        [command 1] ; [command 2]

* To leave stuff in background even if you logout

         nohup ./long_script &

* Change to the previous directory you were working on

        cd -

* Starts a command at the specified time

        echo start_backup.sh | at midnight

* Remembers your most used folders

        'j.py' http://tiny.cc/62qjow  an incredible substitute to browse directories by name instead of 'cd'
        - learn to use 'pushd' to save time navigating folders (j.py is better though)

  - `tee`: allows you to pipe output to a file and stdout at the same time
  - `awk`: finds patterns in files. most useful for filtering fields seperated by white space
  - `tr` : translates characters ie: upper to lowercase, removing whitespace, extra characters.
  - `cut`: used to select a number of characters or columns from an input.
  - `tac`: reverse cat. shows last line at the top
  - `curl`: used for transferring data. useful for testing web connections.
  - `wget`: usually used for downloading files from the web
  - `watch`: used to repeat a command periodically. Useful for watching files or proceses.
  - `head`: shows the beginning of a file(s)
  - `tail`: shows the end of a file(s)

* Explain the following command:
  `(date ; ps -ef | awk '{print $1}' | sort | uniq | wc -l ) >> Activity.log`

  - Shows the date
  - show all processes by users including extra information such as userid
  - select the first column (uid)
  - sort by id
  - remove duplicate userid
  - count number of entries
  - pip to file

* Output redirection

        > file redirects stdout to file
        1> file redirects stdout to file
        2> file redirects stderr to file
        &> file redirects stdout and stderr to file
* Write output to a file

```
cat <<EOF> ~/.kube/config

apiVersion: v1
clusters:
EOF

```


## Bash

```
Login vs Non-Login:
     Login: When you login via SSH or via console without GUI. (Mac: Terminal, iTerm), Fabric
     Non-Login: from desktop if you open xterm (except on mac), screen command
     Test which one: shopt login_shell


Ubuntu:
     Login shell: Loads .profile > source .bashrc
     Non-login(already logged): Loads .bashrc only
     * if .bash_profile is present . it will be loaded first. If you want to load .profile you must source it in bash_profile


Mac:
     Login: Gui, iTerm and Terminal are loaded as login .
               .bash_profile is loaded > source .bashrc

.bashrc - is for bash configs
.profile/.bash_profile : environmentmal variables
```

* Configure defaul shell

```
        defshell -bash
```

* Adding aliases

in your .bashrc

```
        alias dev='ssh fooey@dev.example.com -p 22000'
```

* Make bash history 10,0000

```
        export HISTSIZE=100000 SAVEHIST=100000 HISTFILE=~/.bash_history
```

* Configure command line completion using up and down arrows

```
        Create ~/.inputrc and fill it with this:
        "\e[A": history-search-backward
        "\e[B": history-search-forward
        set show-all-if-ambiguous on
        set completion-ignore-case on
```

* Colorize Bash Prompt

```
        add to .bash_profile
        export PS1="[\[\e[32;1m\]\u@\h \[\e[33;1m\]\W\[\033[m\]]\[\e[37;1m\]\$ "
```

* to run a command from history use exclamation !

```
        !680
```

* Prompt for input in a bash script

```
        read -p “Do you want to continue” variable
```

* Cut off the first column in a text file

```
        cat filename | cut -d" " -f1
```

* Redirection of output

```
        &> for redirection, it redirects both the standard output and standard error
```

* Find what a command does

```
        whatis
        The whatis command displays a summary line from the man page for the specified command.
```

* Navigation

```
        ctrl-w - delete the last word
        ctrl-u - delete start of the line
        ctrl-l - clear the screen
        cd -  : go back to previous working dir
        option-left/right - move word by word
```

* Bash Shebang

```
#!/bin/bash
```

* Loop through text file

```
for repo in $(cat repos.txt)
do
    echo $repo
done
```

* Loop through folders

```
for d in */ ; do
    echo "$d"
    cd $d
    <<comand here>>
    cd ..
done
```

* Base64 Decode

```
    echo "word" | base64 -d
```

* set variable

```
    FOO="bar"
```

* unset variable

```
    unset FOO
```

* recalling your variable by prepending it with a dollar sign ($).

```
    echo $FOO
```

* preserves any special characters that might appear in the variable;

```
    echo "${FOO}"
```

* Prepending

    When you create a variable, the variable is known to your current shell and only your current shell
    You can prepend any number of variables before running a command. Whether the variables are used by the child process is up to the process, but you can pass the variables to it no matter what:

    $ FOO=123 bash
    $ echo $FOO
    123


* Exporting variables

    Another way to make variables available to a child process is the export keyword, a command built into Bash. The export command broadens the scope of whatever variable or variables you specify:

* Bash script header

```
#!/bin/bash
```

* Bash loop

```
    for f in * ;
        do file $f ;
    done
```

    or 1 liner

```
    for f in * ; do convert $f -scale 33% tmp/$f ; done
```

* Zshell

    .zprofile is equivalent to .bash_profile and runs at login, including over SSH
    .zshrc is equivalent to .bashrc and runs for each new Terminal session

* Redirects

```
    # cmd 1> file                         # Redirect stdout to file.
    # cmd 2> file                         # Redirect stderr to file.
    # cmd 1>> file                        # Redirect and append stdout to file.
    # cmd &> file                         # Redirect both stdout and stderr to file.
    # cmd >file 2>&1                      # Redirects stderr to stdout and then to file.
    # cmd1 | cmd2                         # pipe stdout to cmd2
    # cmd1 2>&1 | cmd2                    # pipe stdout and stderr to cmd2
```

* Variables

```
    MESSAGE="Hello World"                        # Assign a string
    PI=3.1415                                    # Assign a decimal number
```

* Arguments

```
    $0, $1, $2, ...                              # $0 is the command itself
    $#                                           # The number of arguments
    $*                                           # All arguments (also $@)
```

* Special Variables

```
        $$                                           # The current process ID
        $?                                           # exit status of last command
        command
        if [ $? != 0 ]; then
            echo "command failed"
        fi
        mypath=`pwd`
        mypath=${mypath}/file.txt
        echo ${mypath##*/}                           # Display the filename only
        echo ${mypath%%.*}                           # Full path without extention
        foo=/tmp/my.dir/filename.tar.gz
        path = ${foo%/*}                             # Full path without extention
        var2=${var:=string}                          # Use var if set, otherwise use string
                                                    # assign string to var and then to var2.
        size=$(stat -c%s "$file")                    # get file size in bourne script
        filesize=${size:=-1}
```

* Constructs

```
    for file in `ls`
    do
        echo $file
    done

    count=0
    while [ $count -lt 5 ]; do
        echo $count
        sleep 1
        count=$(($count + 1))
    done

    myfunction() {
        # $1 is first argument of the function
        find . -type f -name "*.$1" -print
    }
    myfunction "txt"

```

* Generate a file

```
    MYHOME=/home/colin
    cat > testhome.sh << _EOF
    # All of this goes into the file testhome.sh
    if [ -d "$MYHOME" ] ; then
        echo $MYHOME exists
    else
        echo $MYHOME does not exist
    fi
    _EOF
    sh testhome.sh
```
* Assigning output of one command to variable

```
    #!/bin/bash
    for node in $(cat nodes.txt)
    do
        node_name=$(echo $node | tr -d '"');
        echo $node_name
    done
```

* Iterating a json file

```
for r in $(cat repos.json | jq '.[]')
do
    repo_name=$(echo $r | tr -d '"');
    echo $repo_name;
done
```

* Checking for existence of arguments

```
    if [ $# -eq 0 ]; then
        echo "Please enter an argument"
        exit 1
    fi
```

* Check for environment variable

```
    if [ -z "${GITHUB_TOKEN}" ]; then
        echo "Missing GITHUB_TOKEN environment variable"
        exit 1
    fi
```

* Checking the output of last command and prompt to continue

```
     if [[ $? -ne 0 ]]; then
        echo "command failed"
        read ABCD
     fi
```

* Iterate over a list

```
    namespaces=(ns1 ns2 ns3)
    for n in ${namespaces[@]}; do
        echo "*** $n ***" ;
    done
```

* Iterate over a file

```
#!/bin/bash
for repo in $(cat repos.txt)
do
    echo $repo
    read -n 1 # prompt to continue
done
```

* !^

```
!^ maps to the first argument of your latest command.
```

* !$

```
!$ maps to the last argument of your latest command.
```

* !!:2

you could use the !! event designator to select the last command, and the 2 word designator to select the second argument.

* Brace expansion

expanded into ~/test/pics , ~/test/sounds, ~/test/sprites

```
$ mkdir ~/test/{pics,sounds,sprites}
```

A brace expansion can also have a sequence pattern {x..y[..incr]} where x and y are either an integer or a single character, and incr is an optional increment value.

```
touch ~/test/sounds/noise-{1..5}.mp3
```

```
$ touch ~/test/pics/pic{1..10..2}.jpg
$ ls ~/test/pics
pic1.jpg pic3.jpg pic5.jpg pic7.jpg pic9.jpg
```

* Command Expansion

Your shell can replace a command surrounded by $() with its output.

```
$ cat <<EOF > aboutme
My name is $(whoami)
and I live in $HOME
EOF
$ cat aboutme
My name is br
and I live in /home/br
```

for example rename all directories to uppercase

```
$ for dir in */; do
    mv "$dir" "$(echo "$dir" | tr '[:lower:]' '[:upper:]')"
  done
```

* Copy from clipboard into new file

```
cat > generate-conf.sh (ctrl+d = paste)
```


* set -e

The `set -e` option instructs bash to immediately exit if any command [1] has a non-zero exit status. You wouldn't want to set this for your command-line shell, but in a script it's massively helpful. In all widely used general-purpose programming languages, an unhandled runtime error
- whether that's a thrown exception in Java, or a segmentation fault in C, or a syntax error in Python - immediately halts execution of the program; subsequent lines are not executed.

    - By default, bash does not do this. This default behavior is exactly what you want if you are using bash on the command line
    - you don't want a typo to log you out! But in a script, you really want the opposite.
    - If one line in a script fails, but the last line succeeds, the whole script has a successful exit code. That makes it very easy to miss the error.
    - Again, what you want when using bash as your command-line shell and using it in scripts are at odds here. Being intolerant of errors is a lot better in scripts, and that's what set -e gives you.

* set -x

 Enables a mode of the shell where all executed commands are printed to the terminal. In your case it's clearly used for debugging, which is a typical use case for set -x : printing every command as it is executed may help you to visualize the control flow of the script if it is not functioning as expected.

* set -u

Affects variables. When set, a reference to any variable you haven't previously defined - with the exceptions of $* and $@ - is an error, and causes the program to immediately exit. Languages like Python, C, Java and more all behave the same way, for all sorts of good reasons. One is so typos don't create new variables without you realizing it. For example:

    ```
    #!/bin/bash
    firstName="Aaron"
    fullName="$firstname Maxwell"
    echo "$fullName"
    ```
Take a moment and look. Do you see the error? The right-hand side of the third line says "firstname", all lowercase, instead of the camel-cased "firstName". Without the -u option, this will be a silent error. But with the -u option, the script exits on that line with an exit code of 1, printing the message "firstname: unbound variable" to stderr.

This is what you want: have it fail explicitly and immediately, rather than create subtle bugs that may be discovered too late.


* set -o pipefail


30 years ago, when the first users of Bourne shell were burned by this problem, a shell option called “pipefail” was introduced. Enabling this option changes the shell’s behavior so that, when any command in a pipeline series fails, the entire pipeline fails. However, this option is not enabled by default, so it’s widely recommended as best practice that all scripts should start by enabling this (and a few other) (options)[https://sipb.mit.edu/doc/safe-shell/].

This setting prevents errors in a pipeline from being masked. If any command in a pipeline fails, that return code will be used as the return code of the whole pipeline. By default, the pipeline's return code is that of the last command even if it succeeds. Imagine finding a sorted list of matching lines in a file:

    ```
    $ grep some-string /non/existent/file | sort
    grep: /non/existent/file: No such file or directory
    % echo $?
    0
    ```

- Here, grep has an exit code of 2, writes an error message to stderr, and an empty string to stdout.
- This empty string is then passed through sort, which happily accepts it as valid input, and returns a status code of 0.
- This is fine for a command line, but bad for a shell script: you almost certainly want the script to exit right then with a nonzero exit code... like this:

    ```
    $ set -o pipefail
    $ grep some-string /non/existent/file | sort
    grep: /non/existent/file: No such file or directory
    $ echo $?
    2
    ```

* Setting IFS

The IFS variable - which stands for Internal Field Separator - controls what Bash calls word splitting. When set to a string, each character in the string is considered by Bash to separate words. This governs how bash will iterate through a sequence. For example, this script:

    ```
    #!/bin/bash
    IFS=$' '
    items="a b c"
    for x in $items; do
        echo "$x"
    done

    IFS=$'\n'
    for y in $items; do
        echo "$y"
    done
    ... will print out this:

    a
    b
    c
    a b c
    ```
In the first for loop, IFS is set to $' '. (The $'...' syntax creates a string, with backslash-escaped characters replaced with special characters - like "\t" for tab and "\n" for newline.) Within the for loops, x and y are set to whatever bash considers a "word" in the original sequence.

For the first loop, IFS is a space, meaning that words are separated by a space character.
For the second loop, "words" are separated by a newline, which means bash considers the whole value of "items" as a single word. If IFS is more than one character, splitting will be done on any of those characters.

Got all that? The next question is, why are we setting IFS to a string consisting of a tab character and a newline? Because it gives us better behavior when iterating over a loop. By "better", I mean "much less likely to cause surprising and confusing bugs". This is apparent in working with bash arrays:

    ```
    #!/bin/bash
    names=(
    "Aaron Maxwell"
    "Wayne Gretzky"
    "David Beckham"
    )

    echo "With default IFS value..."
    for name in ${names[@]}; do
    echo "$name"
    done

    echo ""
    echo "With strict-mode IFS value..."
    IFS=$'\n\t'
    for name in ${names[@]}; do
    echo "$name"
    done

    ```
    ```
    ## Output
    With default IFS value...
    Aaron
    Maxwell
    Wayne
    Gretzky
    David
    Beckham

    With strict-mode IFS value...
    Aaron Maxwell
    Wayne Gretzky
    David Beckham
    ```
Or consider a script that takes filenames as command line arguments:

    ```
    for arg in $@; do
        echo "doing something with file: $arg"
    done
    ```
If you invoke this as myscript.sh notes todo-list 'My Resume.doc', then with the default IFS value, the third argument will be mis-parsed as two separate files - named "My" and "Resume.doc". When actually it's a file that has a space in it, named "My Resume.doc".

Which behavior is more generally useful? The second, of course - where we have the ability to not split on spaces. If we have an array of strings that in general contain spaces, we normally want to iterate through them item by item, and not split an individual item into several.

Setting IFS to $'\n\t' means that word splitting will happen only on newlines and tab characters. This very often produces useful splitting behavior.

By default, bash sets this to $' \n\t' - space, newline, tab - which is too eager.


## Networking


* Show Hostname

```
        hostname -f
```

* Set hostname

```
        hostname acme.dev.nul
        or /etc/sysconfig/network
```

* Change Time Zone

```
        ln -sf /usr/share/zoneinfo/Australia/Sydney /etc/localtime
        export TZ=Australia/Sydney
```

* Show IP

```
        hostname -I
        ip addr show
        sudo ethtool eth0 - show connection status
```

* Set IP

```
        ifconfig eth0 192.168.0.10 netmask 255.255.255.0
        system-config-network
        /etc/sysconfig/network-scripts/
        ip address add 192.168.0.1 dev eth0
```

* Add Default Gateway

```
        route add default gw xx.xx.xx.1
```

* Show Routes

```
netstat -r
```

* Restart Nic

```
        service network restart
        /etc/init.d/network restart
        ifup eth0
```

* Configure DNS

```
        nano /etc/resolv.conf
```

* Configure DNS for specific suffix

```
         cat /etc/resolver/private
         nameserver 192.168.99.100
```

* Query DNS

```
        dig +short txt 20120113._domainkey.gmail.com @8.8.8.8 #query text records
        dig -x host #reverse
        dig +nocmd +noall +answer www.blah.com #shows TTL
        dig +short txt u123455.wl0000.sendgrid.net #query spf txt records
        dig +short mx company.com # query mx records
```

* Wget

```
        * Download file setting target directory:
        wget -P ~/dest/dir www.foo.com/myfile.png
        * Download file but save as different name
        wget -O taglist.zip http://www.vim.org/scripts/download_script.php
```

* Curl

```
        curl -I www.server.com			# -I to show headers only, -i to show headers
        curl -D- www.server.com |less  # shows detailed tcp stuff

```

* Curl loop

```
        while true; do curl --write-out " - HTTP Response: %{http_code} - Total time: %{time_total} \n" https://google.com; done #continous
```

* Show IP address

```
curl ipinfo.io
```

* Siege

```
        * Benchmark  20 connections for 30 seconds.
        siege -c20 www.google.com -b -t30s
```

* Ngrep

```
        * Similar to wireshark
        ngrep -q -W byline "^(GET|POST) .*" # -W byline  preserves linesbreaks, -q  #supresses output about 		non-matching packets
        ngrep -q -W byline "search" host www.google.com and port 80
```

        * Show packets going to a website on network

```
        ngrep -d mywebsite
```

## Netcat


* Portscan

```
        nc -z example.com 20-100 	#scan port 20-100
```
* Copy files between two hosts

```
        Server: $ nc -l 9090 | tar -xzf -
        Client: tar -czf dir/ | nc server 9090
```

* Expose a shell over port 8080

```
        server:
        $ mkfifo backpipe $ nc -l 8080  0<backpipe | /bin/bash > backpipe
        Client:
        nc example.com 8080
```

* receive file

```
        nc -l 9931 > bigfile
```

* send file

```
        cat bigfile | nc ipaddress 9931
```

```
        nc -l -p 1234 #starts a server on port 1234
        nc destination_host 1234 # connect to server from client
        tar cfp - /some/dir | compress -c | nc -w 3 destination_host 1234 # compress file and send to remove
```


## Sshuttle


* Tunnel traffic to any server you have ssh access to including dns

```
        sshuttle -r <server> --dns 0/0
```

## Mitmproxy

 Allows you to inspect https traffic

* Automatically strip all cache control headers and make sure you always get fresh connection

```
        mitmproxy --anticache
```

* Record a session

```
        mitmdump -w user-signup
```
* Replay a sessio

```
        mitmdump -c user-signup | tail -n1 | grep 200 && echo "OK" || echo "FAIL"
```
* Disable ping to avoid ICMP flood

```
        Set following in /etc/sysctl.conf : net.ipv4.icmp_echo_ignore_all = 1
        Then “sysctl -p”
```

* Show Public IP Address

```
        ip addr show eth0 | grep inet | awk '{ print $2; }' | sed 's/\/.*$//'
```
* Show SYN Flood

```
        ss -a | grep SYN-RECV | awk '{print $4}' | awk -F":" '{print $1}' | sort | uniq -c | sort -n
        or
        netstat -antp | grep SYN_RECV|awk '{print $4}'|sort|uniq -c | sort -n
```


## Screen

* Config File

```
        ~/.screenrc
```

* Commands

```
screen -ls #show all screens
CTRL a w # which screens are available
CTRL a 0 # go to window 0
CTRL a 1 # go to window 1
CTRl a D # detach from current session
CTRL a c # create a new screen
CTRL a n # go to next screen
CTRL a A # rename session name
CTRL a S # split screen horizontal
CTRL a TAB # move to next split screen
CTRL a | # split screen vertical
CTRL A X # close current split screen
CTRL+a - switches to last window
Exit # kill current session
screen -r #reattach to screen
```

## Python


* update pip (Python package manager):

```
        pip install -U pip
```
* search pip repos

```
        pip
```
* create a virtual python environment

```
        virtualenv [dirname] --no-site-packages
```
* connect to a virtual python environment

```
        source [dirname]/bin/activate
```
* disconnect from a python environment:

```
        deactivate
```
* install package into virtual python environment from outsie:

```
        pip install [packagename]==[version_number] -E [dirname]
```
* export python virtual environment into a shareable format:

```
        pip freeze -E [dirname] > requirements.txt
```
* import python virtual environment from a requirements.txt file:

```
        pip install -E [dirname] -r requirements.txt
```
* Share all files in current folder over port 8080

```
        python -m SimpleHTTPServer 8080
```



## Firewall


* Show config

```
        iptables -L -v
```
* Edit config

```
        /etc/sysconfig/iptables
```
* Allow connections for all tcp connections attempts at web connections.

```
        sudo iptables -I INPUT 2 -p tcp  --dport 80 -j ACCEPT
```

* Lockdown connections to any IP address lying in the range of 192.168.1.0 - 192.168.1.255

```
        sudo iptables -I INPUT 2 -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT
```
* Lockdown SSH to kick anyone after 3 attempts

```
Replace default ssh rule with this one.
The first rule records the IP address of each attempt to access port 22 using the recent module.
The second rule checks to see if that IP address has attempted to connect 4 or more times within the last 60 seconds, and if not then the packet is accepted.
Note this rule would require a default policy of DROP on the input chain.

iptables -A INPUT -p tcp --dport 22 -m recent --set --name ssh --rsource
iptables -A INPUT -p tcp --dport 22 -m recent ! --rcheck --seconds 60 --hitcount 4 --name ssh --rsource -j ACCEPT
```

* Command switches


```
        -A      	Append
        -I          Inserts rule to position in chain
        -m          Connection State
        -j          jump to target: Accept, Drop, Log
        --dport     destination port
        -s          source ip
        -p protocol
```

* Save config

```
/etc/init.d/iptables save
```

* Restart Iptables

```
sudo /sbin/service iptables restart
```


## SELINUX


* Disable SE Linux


```
cat /etc/selinux/config
SELINUX=disabled
SELINUXTYPE=targeted
```

## YUM

* Check repositories:

```
nano /etc/yum.repos.d/CentOS-Base.repo
sudo yum repolist
```

* Install Repositories

```
rpm -Uvh http://packages.sw.be/rpmforge-release/rpmforge-release-0.5.2-2.el6.rf.x86_64.rpm
```


* Install package

```
yum install PACKAGENAME
```

* Remove package

```
yum remove PACKAGENAME
```

* Update package

```
yum update PACKAGENAME
```


* List available updates

```
yum list updates
```

* Update system

```
yum update
```

* Upgrade system to newest release (dangerous!)

```
yum upgrade
```

* Show package

```
yum list PACKAGENAME
```

* Search package repositories

```
yum search SEARCHSTRING
```

* Search particular version of a package

```
yum --showduplicates list httpd | expand
```

* List package groups

```
yum grouplist
```

* Install package group

```
yum groupinstall 'GROUP NAME'
```

* Update package group

```
yum groupupdate 'GROUP NAME'
```

* Remove package group

```
yum groupremove 'GROUP NAME'
```

* Install utitilites you would need to install most commonly

```
yum groupinstall "Development Tools"
```

* Show installed packages

```
yum list installed
```

* Show available updates

```
yum list updates
```


## Cron

* Cron files

```
/etc/cron.allow  # users allowed to submit jobs
```

* Jobs submitted from following dirs


```
/etc/crontab # root only jobs
/etc/cron.d #
/etc/cron.hourly #files placed in this dir run hourly
/var/spool/cron/username # created for user when run crontab -e
```


* Crontab Commands

```
export EDITOR=nano to specify a editor to open crontab file.
crontab -e    		Edit your crontab file, or create one if it doesn’t already exist.
crontab -l      	Display your crontab file.
crontab -r      	Remove your crontab file.
crontab -v      	Display the last time you edited your crontab file. (This option is only 					available on a few systems.)
```

* Crontab file

```
Crontab syntax :
A crontab file has five fields for specifying day , date and time followed by the command to be run at that interval.
*     *     *   *    *        command to be executed
-     -     -   -    -
|     |     |   |    |
|     |     |   |    +----- day of week (0 - 6) (Sunday=0)
|     |     |   +------- month (1 - 12)
|     |     +--------- day of        month (1 - 31)
|     +----------- hour (0 - 23)
+------------- min (0 - 59)
```

* To Use Env Variables

```
Example:
* In crontab -e file:

SHELL=/bin/bash
*/1 * * * * $HOME/cron_job.sh

* In cron_job.sh file:
#!/bin/bash
source $HOME/.bash_profile
some_other_cmd
```

* To Run with Virtual Env

```
* in cron.sh
#!/bin/bash
source $HOME/.bash_profile
source /home/user/envs/project/bin/activate
python ~/projects/myproject/myproject/cron.py >> ~/cronstatus.log

* in cron.py

import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "myproject.settings")
from django.conf import settings
```

* Generate log file

```
30 18 * * * rm /home/someuser/tmp/* > /home/someuser/cronlogs/clean_tmp_dir.log
```

* Find out what cron jobs are running

```
ls /etc/cron* + cat for user in $(cat /etc/passwd | cut -f1 -d:); do crontab -l -u $user; done
```

* To find out where is cron log

```
grep -ic cron /var/log/* | grep -v :0
grep cron /etc/rsyslog.conf
```

* Check if cron configured to log

```
cat /etc/default/cron
look for EXTRA_OPTS="-L 2” -L is how verbose
```

* Check cron log

        mailx


#SSH

* SSHD Config

```
        nano /etc/ssh/sshd_config
```

* User Config File

```
        ~/.ssh/config
```

* Example Config

```
        Host dev
            HostName dev.example.com
            Port 22000
            User phooey
            IdentityFile ~/.ssh/github.key
```

* Port Forwarding

* Local client  will use 9906 and use ssh and connect over to 3306

```
        ssh -f -N -L 9906:127.0.0.1:3306 user@remoteserver.com
```

* Lightweight Proxy for Geoblocked content:

```
        ssh -D 9090 user@remoteserver.com

        Exposes the local port 9090 as a SOCKS proxy. You can then alter your browser settings to use your local SOCKS proxy to route browsing traffic.
```

* Port Forwarding Shortcut

```
    Add this to your ssh config to make it easier to call tunnel

        Host tunnel
            Host name remoteserver.com
            Local forward 9906 127.0.0.1:3306

        ssh -f -N tunnel
```

* Create a new user on the server

```
    Generate a SSH key on local machine
    ssh-keygen -t rsa -C "your_email@example.com"

    Upload the key to the server and add it website user’s authorised keys
   scp i secure_keypair.pem ~/.ssh/id_rsa.pub ec2-user@newwebsite.com:/tmp/
     cd ~/
      mkdir .ssh
      cat /tmp/id_rsa.pub > .ssh/authorized_keys
      chmod 700 .ssh
      chmod 600 .ssh/authorized_keys
    sudo rm /tmp/id_rsa.pub

    Or Upload key to server ussing ssh-copy-id
    ssh-copy-id [-i [identity_file]] [user@]machine
```

* Configure SSH Login using Keys

```
        nano /home/deploy/.ssh/authorized_keys

        Add the contents of the id_rsa.pub on your local machine and any other public keys that you want to have access to this server to this file

        chmod 600 .ssh/authorized_keys
```

* Configure SSH For Certain Users or logins

```
        nano /etc/ssh/sshd_config

        Add these lines to the file, inserting the ip address from where you will be connecting:

        PermitRootLogin no

        PasswordAuthentication no

        AllowUsers user@(your-ip) user@(another-ip-if-any)
```

* Run Commands on remote machine

```
        ssh -l <username> <servername> "/bin/cat -n /etc/group"
```

* Access Localhost pages on remote system

```
Note that if you are working with a remote system via SSH, you can't directly access the remote box's localhost URL. A solution to this is to simply forward port from the remote machine to your local machine:

ssh -f -N -L 8081:localhost:8081 your_user@your_remote_machine

Now you can access http://localhost:8081 and it will be as if you would issue the request from the remote machine.
```

* Prevent Idle SSH sessions being killed

```
    Client config

        ServerAliveInterval = 60

    Server config

        ClientAliveInternal = 60
```

* Retreive the public key from a private key

```
        ssh-keygen -y -e -f myfile.pem
```

* Enable Bastion Host

On local machine enable SSH Agent forwarding

```
        ssh -A user@bastion

        or

        Host bastion
              ForwardAgent yes
```

Then configure ProxyCommand setting for the remote instances in your SSH configuration file.

```
        Host private1
              IdentityFile ~/.ssh/rsa_private_key
              ProxyCommand ssh user@bastion -W %h:%p

        Host bastion
              IdentityFile ~/.ssh/bastion_rsa_key
              ForwardAgent yes
```

Finally, connect to private instance

```
        ssh user@private1
```

SSH will establish a connection to the bastion host and then from the bastion host connect to “private1”, using the specified keys at each step along the way.


* SSH Multiplexing

SSH multiplexing is the ability to carry multiple SSH sessions over a single TCP connection. This can result in speed increases that can add up when repeatedly running commands against remote SSH hosts.

```
        Host demo-server.domain.com
              ControlPath ~/.ssh/cm-%r@%h:%p
              ControlMaster auto
              ControlPersist 10m
```

The ControlPath entry specifies where to store the “control socket” for the multiplexed connections. In this case, %r refers to the remote login name, %h refers to the target host name, and %p refers to the destination port.

The ControlMaster setting is what activates multiplexing. With the auto setting, SSH will try to use a master connection if one exists, but if one doesn’t exist it will create a new one (this is probably the most flexible approach, but you can refer to ssh-config(5) for more details on the other settings).

Finally, the ControlPersist setting keeps the master connection alive for the specified period of time after it has remained idle (no connections).

* Ansible Through Bastion


Custom SSH configuration file is useless without explicitly telling Ansible to use these settings when connecting to Ansible-managed hosts. This is accomplished by creating (or modifying) ansible.cfg and adding the following setings:

```
    [ssh_connection]
    ssh_args = -F ./ssh.cfg -o ControlMaster=auto -o ControlPersist=30m
    control_path = ~/.ssh/ansible-%%r@%%h:%%p
```

* Do programs remain running when you disconnect?

        The new default is to kill all children of a terminating login session, regardless of what historically valid precautions were taken to prevent this. The behavior can be changed by setting KillUserProcesses=no in /etc/systemd/logind.conf. When the SSH daemon process associated with your connection decides that your connection is dead, it sends a hangup signal (SIGHUP) to the login shell. This notifies the shell that you've vanished and that it should begin cleaning up after itself. What happens at this point is shell specific (search its documentation page for "HUP"), but for the most part it will start sending SIGHUP to running jobs associated with it before terminating. Each of those processes, in turn, will do whatever they're configured to do on receipt of that signal. Processes that were invoked with a prefixed nohup command. (i.e. "don't hang up on this") Daemons interpret the HUP signal differently; since they do not have a controlling terminal and do not automatically receive a HUP signal

* Access RDS in a Private Subnet from Local Machine

```
ssh -i "Private_key.pem" -f -N -L 3306:RDS_Instance_Endpoint:3306 ec2-user@EC2-Instance_Endpoint -v
```


```
ssh -i  ~/.ssh/my.key -f -N -L  \
3306:rdshostname.cluster-xyz.us-west-2.rds.amazonaws.com:3306 \
ec2-user@ec1-2-3-4.us-west-2.compute.amazonaws.com -v
```

## Apache

* Install

```
        sudo yum install httpd mod_ssl
        sudo yum install httpd24 mod_ssl
```

* Make DocumentRoot

```
        mkdir /var/www/website.com
```

* Edit config

```
        sudo nano /etc/httpd/conf/httpd.conf
```

* ServerAdmin

```
        ServerAdmin admin@website.com
```

* ServerName

```
        www.website.com
```
* DocumentRoot

```
        DocumentRoot "/var/www/website.com"
```

* Directory Options

```
        <Directory "/var/www/website.com">
        Options FollowSymLinks 	#Comment out Indexes to prevent browsing of directories
```

* ServerTokens

```
        ServerTokens Prod 	# only shows Apache
        * Default: full
```

* Timeout

```
        Timeout 30  # is the max time to wait for a response, action it and respond. Forces visitors to wait in line.
        * Default : 60
```

* MaxKeepAliveRequests

```
        MaxKeepAliveRequests 200 #max number of requests per connection
        *Default : 100
```

* KeepAliveTimeout

```
        KeepAliveTimeout 3 #time that the connection waits for client to request something. But new connections will be on hold. Lower is best
        * Default : 5
```

* LoadModule

```
Remove Following
LoadModule auth_basic_module modules/mod_auth_basic.so  -basic auth-
LoadModule auth_digest_module modules/mod_auth_digest.so - md5 authentication
LoadModule authn_file_module modules/mod_authn_file.so - auth using text files
LoadModule authn_alias_module modules/mod_authn_alias.so - mapping to different parts of file system
LoadModule authn_anon_module modules/mod_authn_anon.so - allows anonymous access to authenticated areas
LoadModule authn_dbm_module modules/mod_authn_dbm.so - auth using dbm files
LoadModule authn_default_module modules/mod_authn_default.so -  #doesnt exist in 2.4?
LoadModule authz_host_module modules/mod_authz_host.so  - auth based on hostname
LoadModule authz_user_module modules/mod_authz_user.so - user auth?
LoadModule authz_owner_module modules/mod_authz_owner.so - auth based on file owner
LoadModule authz_groupfile_module modules/mod_authz_groupfile.so - auth based on plaintext file
LoadModule authz_dbm_module modules/mod_authz_dbm.so
LoadModule authz_default_module modules/mod_authz_default.so
#LoadModule ldap_module modules/mod_ldap.so  -  ldap connection pooling and caching
#LoadModule authnz_ldap_module modules/mod_authnz_ldap.so - ldap auth
LoadModule include_module modules/mod_include.so - server parsed html docs
LoadModule log_config_module modules/mod_log_config.so - log requests to the server
LoadModule logio_module modules/mod_logio.so - logging of input output bytes
#LoadModule env_module modules/mod_env.so - modifies environment for cgi files
#LoadModule ext_filter_module modules/mod_ext_filter.so - pass responses to a filter before client (potentially need)
LoadModule mime_magic_module modules/mod_mime_magic.so
LoadModule expires_module modules/mod_expires.so - creation of expires http headers
LoadModule deflate_module modules/mod_deflate.so -compress content
LoadModule headers_module modules/mod_headers.so - customized headers
#LoadModule usertrack_module modules/mod_usertrack.so - clickstream logging
LoadModule setenvif_module modules/mod_setenvif.so - set env variables  based on request
LoadModule mime_module modules/mod_mime.so - associates extension with content type
#LoadModule dav_module modules/mod_dav.so - webdav
#LoadModule status_module modules/mod_status.so - info on server perf and activity
LoadModule autoindex_module modules/mod_autoindex.so -creates indexes
#LoadModule info_module modules/mod_info.so - overview of server config
#LoadModule dav_fs_module modules/mod_dav_fs.so -webdav
LoadModule vhost_alias_module modules/mod_vhost_alias.so
LoadModule negotiation_module modules/mod_negotiation.so
LoadModule dir_module modules/mod_dir.so
#LoadModule actions_module modules/mod_actions.so - executes cgi scripts based on media type
LoadModule speling_module modules/mod_speling.so - corrects incorrect urls
#LoadModule userdir_module modules/mod_userdir.so - allows access to ~/john
LoadModule alias_module modules/mod_alias.so
LoadModule substitute_module modules/mod_substitute.so
LoadModule rewrite_module modules/mod_rewrite.so
#LoadModule proxy_module modules/mod_proxy.so
#LoadModule proxy_balancer_module modules/mod_proxy_balancer.so
#LoadModule proxy_ftp_module modules/mod_proxy_ftp.so
#LoadModule proxy_http_module modules/mod_proxy_http.so
#LoadModule proxy_ajp_module modules/mod_proxy_ajp.so
#LoadModule proxy_connect_module modules/mod_proxy_connect.so
LoadModule cache_module modules/mod_cache.so
#LoadModule suexec_module modules/mod_suexec.so - allow cgi scripts to run as specific user
LoadModule disk_cache_module modules/mod_disk_cache.so
#LoadModule cgi_module modules/mod_cgi.so - excute cgi
#LoadModule version_module modules/mod_version.so - used if you want directives for different httpd versions
#LoadModule mod_lua - provides interfaces for lua programming language
```

* Server Signature

```
        ServerSignature Off
        * Default: On
```

* Virtual Host

```
#Virtual Host
<VirtualHost *:80>
    ServerAdmin admin@website.com
    DocumentRoot /var/www/website.com
    ServerName www.website.com
    ErrorLog /var/log/httpd/website-error_log.log
    CustomLog /var/log/httpd/website-access_log.log common
    #only allow betauser while in beta
    AuthType Basic
    AuthName "Invitation Only"
    AuthUserFile /var/www/passwd/passwords
    Require user betauser

    <Directory "/var/www/website.com">
        # Enable rewrite engine and route requests to framework
        RewriteEngine On
        RewriteBase /
        RewriteCond %{REQUEST_FILENAME} !-l
        RewriteCond %{REQUEST_FILENAME} !-f
        RewriteCond %{REQUEST_FILENAME} !-d
        RewriteCond $1 !^(api|auth)
        RewriteRule ^(.*)$ index.php/$1 [L,QSA]
        RewriteRule ^api/.* api/index.php [L,QSA]
        RewriteRule ^auth/.* auth/index.php [L,QSA]

        # Disable ETags
        <IfModule mod_headers.c>
        Header Unset ETag
        FileETag none
        </IfModule>

        # Default expires header if none specified (stay in browser cache for 7 days)
        <IfModule mod_expires.c>
        ExpiresActive On
        ExpiresDefault A604800
        </IfModule>
    </Directory>

</VirtualHost>
```

* Cloudflare

Restrict /admin website to only canada and australia


```
    SetEnvIf CF-IPCountry AU AllowCountry=1
    SetEnvIf CF-IPCountry CA AllowCountry=1
    <Directory /var/www/website.com/admin>
      <RequireAll>
        Require env AllowCountry
      </RequireAll>
    </Directory>
```


* Pagespeed

```
<IfModule pagespeed_module>
    # Uncomment the following line if you want to disable statistics entirely.
    # ModPagespeedStatistics off

    # This page shows statistics about the mod_pagespeed module.
    <Location /mod_pagespeed_statistics>
        Order allow,deny
        # One may insert other "Allow from" lines to add hosts that are
        # allowed to look at generated statistics.  Another possibility is
        # to comment out the "Order" and "Allow" options from the config
        # file, to allow any client that can reach the server to examine
        # statistics.  This might be appropriate in an experimental setup or
        # if the Apache server is protected by a reverse proxy that will
        # filter URLs to avoid exposing these statistics, which may
        # reveal site metrics that should not be shared otherwise.
        Allow from localhost
        Allow from 127.0.0.1
        SetHandler mod_pagespeed_statistics
    </Location>

    # This handles the client-side instrumentation callbacks which are injected
    # by the add_instrumentation filter.
    <Location /mod_pagespeed_beacon>
          SetHandler mod_pagespeed_beacon
    </Location>
</IfModule>
```

* Enable Compression

```
        #AdditionalCompression
        AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css text/javascript application/x-javascript
```

* Add permissions writable directories

```
        chown apache:apache -R /var/www/website.com/images/dir1
        chown apache:apache -R /var/www/website.com/images/dir2
```

* Restart

```
        /etc/init.d/httpd restart
```

* Autostart

```
        sudo /sbin/chkconfig --levels 235 httpd on
```

* Reload Config

```
        sudo /etc/init.d/httpd reload
```

* See loaded modules

```
        /usr/sbin/httpd -M
```

* Security Testing

```
        wget -P ~/tools http://www.cirt.net/nikto/nikto-current.tar.gz
        tar -xzvf nikto-current.tar.gz
        perl nikto.pl -h localhost
```

## SSL

 * Install tools

        yum install openssl openssl-devel
        or yum install crypto-utils

 * Generate Private Key

        openssl genrsa -out my-private-key.pem 2048
        or genkey --days 365 servername.domain.com

* Create CSR

        openssl req -sha256 -new -key ~/my-private-key.pem -out ~/domain.com.csr

* Create a SAN config

```

        [ req ]
        prompt = no
        default_bits       = 2048
        distinguished_name = req_distinguished_name
        req_extensions     = req_ext
        [ req_distinguished_name ]
        countryName                = CA
        stateOrProvinceName        = Ontario
        localityName               = Toronto
        organizationName           = Company
        organizationalUnitName     = MyBusinessUnit
        commonName                 = server.domain.com
        [ req_ext ]
        subjectAltName = @alt_names
        [alt_names]
        DNS.1   = server1.domain.com
        DNS.2   = server2.domain.com
```

* Create CSR with SAN config

        openssl req -new -sha256 -key my-private-key.pem -out domain.com.csr -config san.cnf

* Verify SAN on cert

        openssl req -noout -text -in domain.com.csr | grep DNS

* Convert Cert to PKCS12

        openssl pkcs12 -export -out  domain.com.p12 -inkey my-private-key.pem -in cert.cer

* Install Cert

        Copy to  /etc/httpd/conf/ssl.crt/
        genkey will output
        /etc/pki/tls/private/ #privatekey
        /etc/pki/certs/ #public key

* View Cert

        openssl x509 -in cerfile.cer -noout –text

* Create a self-signed certificate

        openssl x509 -req -days 365 -in my.csr -signkey my-private-key.pem -out my-self-signed.pem

* Installing Root CA

Installing a CA

Copy your certificate in PEM format (the format that has ----BEGIN CERTIFICATE---- in it) into /usr/local/share/ca-certificates and name it with a .crt file extension.

Then run

    sudo update-ca-certificates.

Caveats: This installation only affects products that use this certificate store. Some products may use other certificate stores; if you use those products, you'll need to add this CA certificate to those other certificate stores, too. (Firefox Instructions, Chrome Instructions, Java Instructions)

* Testing The Root CA is installed

You can verify if this worked by looking for the certificate that you just added in /etc/ssl/certs/ca-certificates.crt (which is just a long list of all of your trusted CA's concatenated together).

You can also use OpenSSL's s_client by trying to connect to a server that you know is using a certificate signed by the CA that you just installed.

    $ openssl s_client -connect foo.whatever.com:443 -CApath /etc/ssl/certs

    CONNECTED(00000003)
    depth=1 C = US, ST = Virginia, O = "Whatever, Inc.", CN = whatever.com, emailAddress = admin@whatever.com
    verify return:1
    depth=0 C = US, ST = Virginia, L = Arlington, O = "Whatever, Inc.", CN = foo.whatever.com
    verify return:1
    ---
    Certificate chain
     0 s:/C=US/ST=Virginia/L=Arlington/O=Whatever, Inc./CN=foo.whatever.com
       i:/C=US/ST=Virginia/O=Whatever, Inc./CN=whatever.com/emailAddress=admin@whatever.com

    ... snip lots of output ...

        Key-Arg   : None
        PSK identity: None
        PSK identity hint: None
        SRP username: None
        Start Time: 1392837700
        Timeout   : 300 (sec)
        Verify return code: 0 (ok)


    The first thing to look for is the certificate chain near the top of the output. This should show the CA as the issuer (next to i:). This tells you that the server is presenting a certificate signed by the CA you're installing. Second, look for the verify return code at the end to be set to 0 (ok).


* Test SSL certificates

        openssl s_client -connect name.server.io:443


* Certificate Formats

.csr - This is a Certificate Signing Request. Some applications can generate these for submission to certificate-authorities. The actual format is PKCS10 which is defined in RFC 2986. It includes some/all of the key details of the requested certificate such as subject, organization, state, whatnot, as well as the public key of the certificate to get signed. These get signed by the CA and a certificate is returned. The returned certificate is the public certificate (which includes the public key but not the private key), which itself can be in a couple of formats.

.pem - Defined in RFCs 1421 through 1424, this is a container format that may include just the public certificate (such as with Apache installs, and CA certificate files /etc/ssl/certs), or may include an entire certificate chain including public key, private key, and root certificates. Confusingly, it may also encode a CSR (e.g. as used here) as the PKCS10 format can be translated into PEM. The name is from Privacy Enhanced Mail (PEM), a failed method for secure email but the container format it used lives on, and is a base64 translation of the x509 ASN.1 keys.

.key - This is a PEM formatted file containing just the private-key of a specific certificate and is merely a conventional name and not a standardized one. In Apache installs, this frequently resides in /etc/ssl/private. The rights on these files are very important, and some programs will refuse to load these certificates if they are set wrong.

.pkcs12 .pfx .p12 - Originally defined by RSA in the Public-Key Cryptography Standards (abbreviated PKCS), the "12" variant was originally enhanced by Microsoft, and later submitted as RFC 7292. This is a passworded container format that contains both public and private certificate pairs. Unlike .pem files, this container is fully encrypted. Openssl can turn this into a .pem file with both public and private keys: openssl pkcs12 -in file-to-convert.p12 -out converted-file.pem -nodes
A few other formats that show up from time to time:

.der - A way to encode ASN.1 syntax in binary, a .pem file is just a Base64 encoded .der file. OpenSSL can convert these to .pem (openssl x509 -inform der -in to-convert.der -out converted.pem). Windows sees these as Certificate files. By default, Windows will export certificates as .DER formatted files with a different extension. Like...
.cert .cer .crt - A .pem (or rarely .der) formatted file with a different extension, one that is recognized by Windows Explorer as a certificate, which .pem is not.

.pub - public key created by openssl.

.p7b .keystore - Defined in RFC 2315 as PKCS number 7, this is a format used by Windows for certificate interchange. Java understands these natively, and often uses .keystore as an extension instead. Unlike .pem style certificates, this format has a defined way to include certification-path certificates.

.crl - A certificate revocation list. Certificate Authorities produce these as a way to de-authorize certificates before expiration. You can sometimes download them from CA websites.

In summary, there are four different ways to present certificates and their components:

PEM - Governed by RFCs, its used preferentially by open-source software. It can have a variety of extensions (.pem, .key, .cer, .cert, more)

PKCS7 - An open standard used by Java and supported by Windows. Does not contain private key material.

PKCS12 - A Microsoft private standard that was later defined in an RFC that provides enhanced security versus the plain-text PEM format. This can contain private key material. Its used preferentially by Windows systems, and can be freely converted to PEM format through use of openssl.

DER - The parent format of PEM. It's useful to think of it as a binary version of the base64-encoded PEM file. Not routinely used very much outside of Windows.

## PHP

* Install

        yum install php php-cli php-common php-pecl-memcache php-pear  php-mysql php-xml php-mbstring php-gd php-pdo
        or  (amazon)

        yum install php54 php54-cli php54-common php54-pecl-memcache php54-pear php54-mysql php54-xml php54-mbstring php54-gd php54-pdo

* Configuration File

        nano  /etc/php.ini

* Expose PHP

        expose_php = Off
        * Default: On

* Memory Limit

        memory_limit = 128M
        * Default: 128M (no change)

* Error Log

        error_log = /var/log/php-error.log
        * Defautl: Empty

* Timezone

        date.timezone = "Australia/Sydney"

* Allow Fopen

        allow_url_fopen  = Off
        * Default : On. If enabled, allow_url_fopen allows PHP's file functions to retrieve data from remote locations such as an FTP server or web site, and could lead to code injection vulnerabilities.

* Create the PHP error files

        sudo touch /var/log/php-error.log


## MySQL

* Database types:

```
The two most popular storage engines in MySQL are InnoDB and MyISAM
InnoDB supports some newer features like transactions, row-level locking, foreign keys. It's optimized for read/write high volume operations and high performance.
MyISAM is simpler and better optimized for read only operations. It has limited feature set as compared to InnoDB.
```

* Get help:

        help

* Login to server

        mysql -h mysql–instance1.123456789012.us-east-1.rds.amazonaws.com -P 3306 -u mymasteruser -p

* Create a new Database

        mysqladmin -u root -pmyPassword -v create myDB

* Show databases:

        show databases;

* Secure Installation

        /usr/bin/mysql_secure_installation

* Choose a database to use:

        use [database name here];

* Show database schema:

        show tables;

* Delete database:

        DROP DATABASE [databasename];

* New database:

        CREATE DATABASE [databasename];

* Create a new user:

        CREATE USER [username@localhost] IDENTIFIED BY '[password]' ;

* Show users:

        select * from mysql.user;

* Delete a user:

        delete from mysql.user WHERE User='[user_name]';

* Give user access to all tables (make them root). the "%" means that they can sign in remotely, from any machine, not just localhost.:

        grant all privileges on *.* to someusr@"%" identified by '[password]';


* Give user access to certain database. Only accessable from localhost

        grant all privileges ON myDB.* TO myUser@localhost IDENTIFIED BY 'myPassword';

* give certain privileges to a user on a certain database:

        grant select,insert,update,delete,create,drop on [somedb].* to [someusr]@["%"] identified by '[password]';

* Show all privileges


        select user,host from mysql.user ;

* Tell mysql to use new user priv policies:


        flush privileges;


* change user password:

        use mysql;
        SET PASSWORD FOR 'jeffrey'@'localhost' = PASSWORD('cleartext password');

* update user

        set password='[password]'('[newpassword]') where User='[user_name]' ;

* mysql command line args:

* export text file with commands to rebuild all mysql tables:

        mysqldump [databasename] > [dumpfilename.txt]


* restore from a dump:

        mysql -u [username] -p < [dumpfilename.txt]


* dump entire database:

        mysqldump -u [username] -p --opt [databasename] > [dumpfile.sql]

* restore from entire database dump:

        mysql -u [username] -p --database=[databasename] < [dumpfile.sql]


* install using remi repo since other repos only had version 5.1 instead of 5.5

        yum --enablerepo=remi install mysql-server  mysql mysql-libs


* Config

        sudo nano /etc/my.cnf

* Add performance settings under [mysqld]

        query_cache_size=16M

        thread_cache_size=4

* Start

        sudo /sbin/chkconfig --levels 235 mysqld on
        sudo service mysqld start

* Auto Config

        sudo /usr/bin/mysql_secure_installation

* Manual Config

```
* Login to MySQL
mysql -u root


* Change root password
USE mysql
SET PASSWORD FOR 'root'@'localhost' = PASSWORD('somesecret');
-Remove anonymous user and account without password
DELETE FROM user WHERE password = '';
DELETE FROM user WHERE user.user= '';

-Flush the privileges and drop test DB
FLUSH PRIVILEGES;

DROP DATABASE test;
```

* Backup

        mysqldump -u root -p --all-databases > ~/backup.sql

        http://sourceforge.net/projects/automysqlbackup/


* Import

        sudo mysql -u root -p < backup.sql


*Tuning

        wget -O mysqltuner.pl mysqltuner.pl
        wget --trust-server-names mysqltuner.pl


* Automatically defragment

        Mysqlcheck -o --user=root --password= -A


* Copy DB to Remote Server

        mysqldump dbname -u root -pRootPassword | mysql --host=remotedb.us-east-1.rds.amazonaws.com --port=3306 --user=root -pRemoteRootPassword --database=remoteDbName

* Secure database to one user from command line

        mysql -e "grant all privileges ON myDBname.* TO dbaccount@localhost IDENTIFIED BY 'mypassword';" --user=root --password=myrootpassword

* Troubleshooting


        SHOW PROCESSLIST; show slow transactions
        mysqladmin ext -i1 | grep Threads_running


## Memcache

* Install Memcached

        yum install memcached

* show version

        memcached –i

* Edit Config

        sudo nano /etc/init.d/memcached

* Start

        checkconfig memcached on
        service memcached start

* Install PHP Extension

        yum install php54-pecl-memcache
        add the memcache extension to your php.ini file, usually at /etc/php.ini.
        extension=memcache.so

## GIT

* Install

```
sudo yum install git
```

* Generate key

```
ssh-keygen -t rsa
```
* Start a new git project:

```
git init
```
* Clone a git (target can be specified either locally or remotely, via any number of protocols):
```
git clone [target]
```
* Commit changes to a git:
```
git commit -m "[message]"
```
* Get info on current repository:

```
git status
```
* Show change log for current repository:

```
git log
```

* Update git directory from another repository:

```
git pull [target]
```

* Push branch to other repository:

```
git push [target]
```

* Create a new branch:

```
git branch [branchname]
```
* Switch to target branch:

```
git checkout [branchname]
```

* Delete a branch:

```
git branch -d [branchname]
```

* Merge two branches:

```
git merge [branchname] [branchname]
```

* Contributing

```
1. Fork it
2. Create your feature branch (git checkout -b my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
4. Push to the branch (git push origin my-new-feature)
5. Create a new Pull Request
```

* Branches

```
1. Create a new branch (git branch my-new-feature)
2. Switch to new branch (git checkout my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
4. Push to the branch (git push origin my-new-feature)
5. Switch to master (git checkout master)
6. Merge (git merge my-new-feature)
```

* Ensure ssh-agent is enabled

```
eval "$(ssh-agent -s)"
```

* Add your SSH key to the ssh-agen

```
ssh-add ~/.ssh/id_rsa
```

* See file changes

```
git diff
```

* Git Post-Receive Hook on server

```
cat > hooks/postreceive
#!/bin/sh
GIT_WORK_TREE=/var/www/html
export GIT_WORK_TREE
do your stuff here
chmod +x hooks/postreceive
```

* Add the remote repository to the local repository

```
git push website+master:refs/heads/master [FIRST TIME ONLY]
git push website master                   [ALL OTHER TIMES]
```

* Add empty commit

```
git commit --allow-empty
```

* List all local branches

```
git branch
```

* List referenced remote branches

```
git branch -r
```

* Find which branches are already merged into master and can be removed

```
git checkout master
git branch --merged
```

* Remove all outdated branches with:

```
git branch -d old-merged-feature
```

* Decide what to do with not merged branches

```
git branch --no-merged
```

* Creating a Fork and making Upstream PR

List the current configured remote repository for your fork.

```
git remote -v
```
    Specify a new remote upstream repository that will be synced with the fork.

```
git remote add upstream https://github.com/ORIGINAL_OWNER/ORIGINAL_REPOSITORY.git
```

* Sync a fork

Fetch the branches and their respective commits from the upstream repository. Commits to master will be stored in a local branch, upstream/master

```
git fetch upstream
```

Check out your fork's local master branch

```
git checkout master
```

Merge the changes from upstream/master into your local master branch. This brings your fork's master branch into sync with the upstream repository, without losing your local changes

```
git merge upstream/master
```

* Show dit diff of staged files

```
git diff ---cached
```

* Rebasing

First fetch the new master from the upstream repository, then rebase your work branch on that:

Option 1:
```
git fetch origin            # Updates origin/master
git rebase origin/master    # Rebases current branch onto origin/master
```

Option 2: Newer

```
git pull --rebase origin master
```

* Undo last commit

```
git reset --hard HEAD~1
```

* Move last commit on master to different branch

```
git checkout -b feature/istio-elb-timeout
git merge master
git checkout master
git reset --keep HEAD~1 # Move master back
git checkout feature/istio-elb-timeout
git status
```

* Move currently worked on files to a new branch

```
git stash
git checkout master
git pull
git checkout -b feature/new
git stash pop
```

* Undo deleting a file that was already committed

```
git checkout main -- folder/deletefile.txt
```

## Jq

The '.' in the jq '.' command above is the simplest jq "filter." The dot takes the input JSON and outputs it as is. You can read more about filters here, but the bare minimum to know is that .keyname will filter the result to a property matching that key, and [index] will match an array value at that index

```
$ USERX='{"name":"duchess","city":"Toronto","orders":[{"id":"x","qty":10},{"id":"y","qty":15}]}'
$ echo $USERX | jq '.'
```

And [] will match each item in an array:

```
echo $USERX | jq '.orders[].id'
"x"
"y"
```

Filtering output by value is also handy! Here we use | to output the result of one filter into the input of another filter and select(.qty>10) to select only orders with qty value greater than 10:

```
echo $USERX | jq '.orders[]|select(.qty>10)'
{
  "id": "y",
  "qty": 15
}
```

One more trick: filtering by key name rather than value:

```
$ ORDER='{"user_id":123,"user_name":"duchess","order_id":456,"order_status":"sent","vendor_id":789,"vendor_name":"Abe Books"}'
$ echo $ORDER | jq '.'
{
  "user_id": 123,
  "user_name": "duchess",
  "order_id": 456,
  "order_status": "sent",
  "vendor_id": 789,
  "vendor_name": "Abe Books"
}
$ echo $ORDER | jq 'with_entries(select(.key|match("order_")))'
{
  "order_id": 456,
  "order_status": "sent"
}
(cheat sheet version: with_entries(select(.key|match("KEY FILTER VALUE"))))
```

Selecting multiple fields

```
cat city.json | jq '.tips[] | "\(.name) \(.type) \(.address)- \(.comment)"'
```


## Rsync

* Install

        yum install rsync

* Sync from one server to another

        sudo rsync -avz -e ssh root@prod.server.com:/var/www/server.com /var/www/


## NewRelic

* Install server monitor

        rpm -Uvh http://yum.newrelic.com/pub/newrelic/el5/x86_64/newrelic-repo-5-3.noarch.rpm

        yum install newrelic-sysmond

        nrsysmond-config --set license_key=************

        /etc/init.d/newrelic-sysmond start

* Install php agent

        yum install newrelic-php5

        newrelic-install install

        service httpd restart

        sudo nano newrelic.cfg

        license_key=REPLACE_WITH_REAL_KEY

* Start php agent

        /etc/init.d/newrelic-daemon restart


## Celery

* Run deamon

        celery multi start  w1 -A myapplication --loglevel=info

* Run Flower in Supervisord

        [program:flower]
        command=celery flower --broker=redis://localhost ; the program (relative uses 		PATH, can take args)
        process_name=%(program_name)s ; process_name expr (default %(program_name)s)
        numprocs=1                    ; number of processes copies to start (def 1)
        autostart=true
        user=flower


## Supervisor

* Install

        pip install supervisor

* Autoconfig

        echo_supervisord_conf > /etc/supervisord.conf


* Example Config for Django app


        [program:myapp]
        command=/usr/bin/gunicorn_django -w 4 -b 127.0.0.1:8000
        directory=/home/ec2-user/django/application/app
        user=nobody
        autostart=true
        autorestart=true
        redirect_stderr=True

* Start Daemon

        /usr/bin/supervisord

* Start Application

        * usr/bin/supervisorctl

         supervisorctl {start,status,stop} hello

## Nginx

* Reload Config

        sudo /etc/init.d/nginx reload

* Test Config File

        sudo /etc/init.d/nginx -t

* Worker processes

    To take advantage of SMP and to enable good efficiency I would recommend changing this to read:

        worker_processes  4;

* Max clients

    You can work out the maximum clients value by multiplying this and the worker_processes settings:

        max_clients = worker_processes * worker_connections

* Keepalive

    The default is very high and can easily be reduced to a few seconds (an initial setting of 2 or 3 is a good place to start and you will rarely need more than that)

        keepalive_timeout  0

        # defaul: keepalive_timeout  65;

* Folder Permissions

    As the default permissions only allow us, the 'demo' user, to browse our home folder, let's start off by giving Nginx access to this folder as well:

        chmod 755 /home/demo

        mkdir -p /home/demo/public_html/domain1.com/{public,private,log,backup}

* Example Config for Django

        server {
        listen 80;
        server_name example.org;
        access_log  /var/log/nginx/example.log;

        location /media/ {
                # if asset versioning is used
                if ($query_string) {
                expires max;
                }
            }

        location /admin/media/ {
                # this changes depending on your python version
                root /path/to/test/lib/python2.6/site-packages/django/contrib;
                }

        location / {
                proxy_pass http://127.0.0.1:8000;
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                }

        }




* root

        This is the key to serving static sites. If you are just trying to lay down some html and css, the root directive specifies the directory that you have stored your files in. I like to store my sites in /var/www,


* location

        $uri is whatever someone typed after the domain name is $uri = /whatever.  try_files 		will look in root directory for a file with a name matching the uri. if not, it will 		send to index.html

        Location takes two parameters, a string/regex and a block. The string/regex is a 		matcher for a specific location. So if you wanted anyone who went to example.com/		whatever to hit a specific page, you would use ‘whatever’ as the uri.
        Also note that this / uri will match all urls, since it’s treated as a regex. If you want a location block to match only an exact string, you can preface it with an equals sign, as shown below. But in this case, it’s ok for it to match all urls.

        location = / { ... }

        location / {     try_files $uri $uri/ /index.html;
          }

        We can use another directive inside the block to serve a file called try_files. Try 		files takes a list of filenames or patterns that it will try to find in you root 		directory, and it will serve the first one it finds. For our simple static server, we 		want to try to find a file with the name of whatever comes after the slash, like 		‘whatever.html’. If there is nothing after the slash, it should go for index.html.

* SSL

        ssl on;
        listen 443 default ssl;
        ssl_certificate /etc/nginx/ssl_hostname.com/ssl-unified.crt;
        ssl_certificate_key /etc/nginx/ssl_hostname.com/ssl.key;

* Permissions for SSL Certs

        Nginx's processes are laid out like this:
            - 1 nginx master process running as *root*
            - x nginx workers running as *www-data*
        Nginx's master process reads the SSL key, not the workers. Because of that, we can 		simply allow only root to read the private key

* Permissions for Files

        One permission requirement that is often overlooked is a user needs x permissions in 		every parent directory of a file to access that file. Check the permissions on /, /		home, /home/demo, etc. for www-data x access. My guess is that /home is probably 770 		and www-data can't chdir through it to get to any subdir. If it is, try

        chmod o+x /		home (or whatever dir is denying the request).

        To easily display all the permissions on a path, you can use namei -om /path/to/check

* To Enable services through firewall

        sudo firewall-cmd --permanent --zone=public --add-service=http
        sudo firewall-cmd --permanent --zone=public --add-service=https
        sudo firewall-cmd --reload

* Auto start service

        sudo systemctl enable nginx.service

## Rsyslog

* Config File

        /etc/syslog.conf

* Define where logs are sent

        mail.*  /var/log/maillog  #defines where to send mail logs. use @@hostname to send to 									a remote host over tcp

* Send messages to Loggly over TCP using the template.

        *.*             @@logs-01.loggly.com:514;LogglyFormat

## Tmux

* Commands

        tmux ls = list sessions
        tmux new = new session
        tmux attach = attach to old session, keep existing sessions open
        tmux attach -b =  attach to session, disconnect other connections
        tmux kill-session

* Keys

        Ctrl-b-d = detach from current session
        Ctrl-b-n  = creates new window
        Ctrl-b-0 = go to window 0
        Ctrl-b-tab = toggle between windows
        Ctrl-b-c = create new window
        Ctrl-b-? = see bindings
        Ctrl-b-x = close current window/pane
        Ctrl-b-o = switch to other pane
        Ctrl-b-q = show panes
        Ctrl-b-V = new vertical pane
        Ctrl-b-arrow = switch panes
        Ctrl-b-[-arrow = scroll

## Ansible

* Run Playbook locally
    ansible-playbook -i "localhost," -c local
* finding Modules information:
---------------------------
ansible-doc -l -> to list out all modules
ansible-doc -l | grep package -> to grep specific modules
ansible-doc package -> to list out all information
also >> ansible-doc -s yum -> also works for details of any modules
>> ansible all -m ping -o -> to display in single line
if we are using sudo user then specify -s at the end to run cmd in sudo

## VIM

### moving around
h - right
l - left
j - down
k - up

### line movement
0 or ^  - start of line
$ - end of line
f + any char - find character on line
G - last line in file
gg - first line in file
number + G - move to line number

### word movements
w - move to next word
b - move backwords
e - end of word

### screen movement
control + f - move down screen
control + d - move down half screen

### searching
/ <query>
n - go to next search result
N - go back in results
* - search for the word where your cursor is

### editing
d - delete
d + $ - delete to end of unline
d + e - delete to end of word
d + G - delete to end of the file
dd - delete whole line
dw - delete word

2 dw - delete 2 words
2 dd - delete 2 lines
u - undo

### copying
y - copy
yy - copy whole line
4y - yank/copy 4 lines below
p - paste

### search & replace
:%s/word/newword/g
:%s/word/newword/c - ask for confirmation

% means - replace in whole file

### save
:w - save/write
:q
:q! - quit without save

## SystemD


```
wget https://github.com/prometheus/node_exporter/releases/download/0.11.0/node_exporter-0.11.0.linux-amd64.tar.gz
sudo mv node_exporter /usr/sbin/

sudo adduser prometheus -s /sbin/nologin
sudo nano /usr/lib/systemd/system/node_exporter.service


[Unit]
Description=Prometheus Node Exporter
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/node_exporter -web.listen-address=:11402
Restart=on-abort


[Install]
WantedBy=multi-user.target


sudo systemctl enable node_exporter.service
sudo systemctl start node_exporter.service

```

First set timezone before logging

```
timedatectl list-timezones
sudo timedatectl set-timezone zone
timedatectl status
```

Logs since current boot

```
journalctl -b
```

To enable persistent logging:

```
sudo nano /etc/systemd/journald.conf
. . .
[Journal]
Storage=persistent
```

Show boots

```
journalctl --list-boots
```

Logs since jan

```
journalctl --since "2015-01-10" --until "2015-01-11 03:00"
journalctl --since 09:00 --until "1 hour ago"
journalctl --since yesterday
```

By unit

```
journalctl -u nginx.service -u php-fpm.service --since today
```

By Process ID

```
journalctl _PID=8088
```

By User ID

```
journalctl _UID=33 --since today
```

Truncate output

```
journalctl --no-full
journalclt --no-pager
```

Output to JSON

```
journalctl -b -u nginx -o json-pretty
```

See how much disk is being used

```
journalctl --disk-usage
```

Delete old logs

```
sudo journalctl --vacuum-size=1G
```

## SystemD (Generic)
----

* Create a service

        sudo nano /etc/systemd/system/my.service
        sudo systemctl enable /etc/systemd/system/my.service
        sudo systemctl start my.service

* Edit Service Config

```
[Unit]
Description=My Service
Documentation=https://backplane.io/index
[Service]
TimeoutStartSec=0
ExecStart=/usr/local/bin/somecommand
[Install]
WantedBy=multi-user.target
```

## SQL

WHERE is for rows:
When querying, we can use the WHERE clause to filter the rows we get back. To use WHERE we specify a condition like “population less than 1000”:

```
SELECT *
FROM city
WHERE population < 1000;
```

SELECT is for Columns
Conversely, if we want to get back only certain pieces of data (i.e. columns) of each row, we use SELECT:

```
SELECT name, countrycode
FROM city;
```

Both at the Same Time
And the real power of SQL is that we can combine both together:

```
SELECT name, countrycode
FROM city
WHERE population < 1000;
```

multiple WHERE queries by using AND like:

```
WHERE population < 1000 AND countrycode = 'AIA'
```

JOIN

Actions like WHERE and SELECT act on a single table.
We know how to get city data, but lifeexpectancy exists on the country table.
How do we get them both together? The only way is to create one big table using JOIN.
It connects city.countrycode to country.code. So for each city row, I take the city.countrycode and find the matching country.code row in the country table. Then I take those two rows and add them together. They are now one, larger row.


```
SELECT *
FROM city
JOIN country ON city.countrycode = country.code;
```

Using SELECT, WHERE and JOIN
Create one big table with FROM and JOIN
Pair down the rows with WHERE
Pair down the columns with SELECT

```
SELECT city.name, country.lifeexpectancy
FROM city
JOIN country ON country.code = city.countrycode
WHERE country.lifeexpectancy > 80;
```

GROUP-BY
Grouping in SQL is closer to a process of sorting, then squishing or flattening. SQL calls this flattening aggregation.
Aggregation can take many forms. We’re about to simply count up the number of rows.
Before we start grouping we need to decide which columns to flatten, and which columns to GROUP BY. Both types of columns go in the SELECT clause. For this query, we’re going to use countrycode and language.

Even with all this explanation, GROUP BY can remain a bit baffling. Let’s walk through it one more time step-by-step:

Start with the full, ungrouped table.
Sort all the rows together based on the GROUP BY columns. So in our example: move all the USA rows together, and then all the TUV rows, and so on.
For each group
All of the columns specified in the GROUP BY clause are already the same so they simply collapse down into that value.
For the other columns, they get combined based on the aggregate function. In our case, we COUNT each row that exists and display the final number.

```
SELECT
  countrycode,
  COUNT(language)
FROM countrylanguage
GROUP BY countrycode;
```

Multiply Two Columns:

Our database has a table named purchase with data in the following columns: id, name, price, quantity, and discount_id.
Let’s multiply the price by the quantity of the products to find out how much you paid for each item in your order.

```
SELECT
    name
     price*quantity  AS total_price
FROM purchase;
```

Multiplying from Other Columns

You can also use data from two columns coming from different tables. We have another table in our database named discount that has columns named id and value; the latter represents the percent discount on the item with the given ID.

```
SELECT
    p.name,
     p.price*p.quantity*(100-d.value)/100  AS total_price
FROM purchase p
JOIN discount d ON d.id=p.discount_id;
```

## SQLLite

import CSV data with a single command, the table is created automatically:

```
> .import --csv city.csv city
> select count(*) from city;
1117
```

Data could be exported as SQL, CSV, JSON, even Markdown and HTML. Takes just a couple of commands:

```
.mode json
.output city.json
select city, foundation_year, timezone from city limit 10;
.shell cat city.json
```

Read json

```
select
  json_extract(value, '$.iso.code') as code,
  json_extract(value, '$.iso.number') as num,
  json_extract(value, '$.name') as name,
  json_extract(value, '$.units.major.name') as unit
from
  json_each(readfile('currency.sample.json'))
;
```

## Fish

Reference:
https://github.com/jorgebucaran/fish-cookbook/blob/master/README.md

Only show abbreviated paths

```fish
set fish_prompt_pwd_dir_length 0
```

Find command status

```fish
echo $status
```

Fish shebang

```
#!/usr/bin/env fish
```

Set variable

```
set foo 42
```
The set builtin accepts the following flags to explicitly declare the scope of the variable:

```
-l, --local: available only to the innermost block
-g, --global: available outside blocks and by other functions
-U, --universal: shared between all fish sessions and persisted across restarts of the shell
-x, --export: available to any child process spawned in the current session
```

To set universal variable

```
set -x -U foo 42
```

Export variable

```
set -x foo 42
```

Show all vars

```
set
```

Set path persistently

```
set -U fish_user_paths $fish_user_paths my_path

# or to add a path to your PATH, globally, permanently, across all open shell sessions

fish_add_path /opt/whatever/bin
```

Unset path persistently

```
if set -l index (contains -i $my_path $PATH)
    set -e PATH[$index]
end
```

Make a function

To make this function available in future fish sessions save it to ~/.config/fish/functions/mkdirp.fish. Note: function name and file name should match

```
function mkdirp
    mkdir -p $argv
end
```
or funsave

```
funcsave mkdirp
```


How do I access the arguments passed to a function in fish?
Use the $argv variable.

```
function Foo
    printf "%s\n" $argv
end
```

How do I parse command line arguments in fish?
Use a for loop.

```
for option in $argv
    switch "$option"
        case -f --foo
        case -b --bar
        case \*
            printf "error: Unknown option %s\n" $option
    end
end
```

Where's the .bash_profile or .bashrc equivalent in fish?

```
Your fish configuration is saved to ~/.config/fish/config.fish.
```

To read a file line by line, use the read builtin.

```
while read -la line
    echo $line
end < my_file
```

To do a loop in a 1 liner

```
for i in ns1 ns2 ns2 ; echo $i ; kubectl get pods --namespace=$i; end
```

Loop based on a file

```
for i in *.yaml
  echo $i
end
```

How do I read from stdin in fish?
Use the read builtin.

```
read --prompt "echo 'Name: ' " -l name
```

Redirect stderr to `$my_file`.

```fish
my_command 2> $my_file
```

Redirect stdout to `$my_file`.

```fish
my_command > $my_file
```

Redirect stdout to stderr.

```fish
my_command >&2
```

Redirect stderr to stdout.

```fish
my_command 2>&1
```

## Regex

* Basics

```
[\^$.|?*+()                          # special characters any other will match themselves
\                                    # escapes special characters and treat as literal
*                                    # repeat the previous item zero or more times
.                                    # single character except line break characters
.*                                   # match zero or more characters
^                                    # match at the start of a line/string
$                                    # match at the end of a line/string
.$                                   # match a single character at the end of line/string
^ $                                  # match line with a single space
^[A-Z]                               # match any line beginning with any char from A to Z
* The ^ (caret) fixes your pattern to the beginning of the line. For example the pattern ^1 matches any line starting with a 1.
* The $ (dollar) fixes your pattern to the end of the sentence. For example, 9$ matches any line ending with a 9.
```

## FFMpeg

To use it, replace the libx264 codec with libx265, and push the compression lever further by increasing the CRF value — add, say, 4 or 6, since a reasonable range for H.265 may be 24 to 30. Note that lower CRF values correspond to higher bitrates, and hence produce higher quality videos.

mp4 to lower output

```
ffmpeg -i input.mp4 -vcodec libx265 -crf 28 output.mp4
```

Mov to mp4

```
ffmpeg -i my-video.mov -vcodec h264 -acodec mp2 my-video.mp4
```

## GPG

Install

`brew install gnupg`

Generate key

`gpg --gen-key`

Export your public key on your second computer into an armored blob using the email address you chose when creating the key

`gpg --export --armor -email > pubkey.asc`

Export your public key using the name on the key and base64 encode

`gpg --export "firstname lastname" |  base64`

Import another users public key

`gpg --import pubkey.asc`

Show keys on keyring

`gpg --list-keys`

Encrypt a file using someone elses public key

`gpg --encrypt --recipient "Cory Heath" myriad.pdf`

Decrypt file

`gpg --decrypt myriad.pdf.gpg > myriad.pdf`


## IPFS

Init

```
ipfs init
ipfs daemon
```

To upload to IPFS, all we need to do on our first computer is

`ipfs add myriad.pdf.gpg`

make sure our file is available on IPFS

`ipfs pin ls`


download the posted encrypted file from your first computer from IPFS using the same hash:

`ipfs get QmYqSCWuzG8Cyo4MFQzqKcC14ct4ybAWyrAc9qzdJaFYTL`


## Dig

Install

```
sudo apt update && sudo apt install dnsutils #debian
sudo yum install bind-utils #centos
```

Query the linux.org domain:

```
dig linux.org
```


The first line of the output prints the installed dig version, and the queried domain name. The second line shows the global options (by default, only cmd).

```
; <<>> DiG 9.13.3 <<>> linux.org
;; global options: +cmd
```
If you don’t want those lines to be included in the output, use the +nocmd option. This option must be the very first one after the dig command.

The next section includes technical details about the answer received from the requested authority (DNS server). The header shows the opcode (the action performed by dig) and the status of the action. In this example, the status is NOERROR, which means that the requested authority served the query without any issue.

```
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 37159
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 2, ADDITIONAL: 5
```
This section can be removed using the +nocomments option, which also disables some other section’s headers.

The “OPT” pseudo section is shown only in the newer versions of the dig utility. You can read more about the Extension mechanisms for DNS (EDNS) here .

```
;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
```
To exclude this section from the output, use the +noedns option.

In the “QUESTION” section dig shows the query (question). By default, dig requests the A record.

```
;; QUESTION SECTION:
;linux.org.			IN	A
```
You can disable this section using the +noquestion option.

The “ANSWER” section provides us with an answer to our question. As we already mentioned, by default dig will request the A record. Here, we can see that the domain linux.org points to the 104.18.59.123 IP address.

```
;; ANSWER SECTION:
linux.org.		300	IN	A	104.18.59.123
linux.org.		300	IN	A	104.18.58.123
```
Usually, you do not want to turn off the answer, but you can remove this section from the output using the +noanswer option.

The “AUTHORITY” section tells us what server(s) are the authority for answering DNS queries about the queried domain.

```
;; AUTHORITY SECTION:
linux.org.		86379	IN	NS	lia.ns.cloudflare.com.
linux.org.		86379	IN	NS	mark.ns.cloudflare.com.
```
You can disable this section of the output using the +noauthority option.

The “ADDITIONAL” section gives us information about the IP addresses of the authoritative DNS servers shown in the authority section.

```
;; ADDITIONAL SECTION:
lia.ns.cloudflare.com.	84354	IN	A	173.245.58.185
lia.ns.cloudflare.com.	170762	IN	AAAA	2400:cb00:2049:1::adf5:3ab9
mark.ns.cloudflare.com.	170734	IN	A	173.245.59.130
mark.ns.cloudflare.com.	170734	IN	AAAA	2400:cb00:2049:1::adf5:3b82
```
The +noadditional option disables the additional section of a reply.

The last section of the dig output includes statistics about the query.

```
;; Query time: 58 msec
;; SERVER: 192.168.1.1#53(192.168.1.1)
;; WHEN: Fri Oct 12 11:46:46 CEST 2018
;; MSG SIZE  rcvd: 212
```
You can disable this part with the +nostats option.

Printing Only the Answer
Generally, you would want to get only a short answer to your dig query.

1. Get a Short Answer
To get a short answer to your query, use the +short option:

```
dig linux.org +short

104.18.59.123
104.18.58.123
```
The output will include only the IP addresses of the A record.

2. Get a Detailed Answer

For more a detailed answer, turn off all the results using the +noall options and then turn on only the answer section with the +answer option.

```
dig linux.org +noall +answer

; <<>> DiG 9.13.3 <<>> linux.org +noall +answer
;; global options: +cmd
linux.org.		67	IN	A	104.18.58.123
linux.org.		67	IN	A	104.18.59.123
```
Query Specific Name Server
By default, if no name server is specified, dig uses the servers listed in /etc/resolv.conf file.

To specify a name server against which the query will be executed, use the @ (at) symbol followed by the name server IP address or hostname.
For example, to query the Google name server (8.8.8.8) for information about the linux.org domain you would use:

```
dig linux.org @8.8.8.8

; <<>> DiG 9.13.3 <<>> linux.org @8.8.8.8
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 39110
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;linux.org.			IN	A

;; ANSWER SECTION:
linux.org.		299	IN	A	104.18.58.123
linux.org.		299	IN	A	104.18.59.123

;; Query time: 54 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Fri Oct 12 14:28:01 CEST 2018
;; MSG SIZE  rcvd: 70
```

Query a Record Type
Dig allows you to perform any valid DNS query by appending the record type to the end of the query. In the following section, we will show you examples of how to search for the most common records, such as A (the IP address), CNAME (canonical name), TXT (text record), MX (mail exchanger), and NS (name servers).

1. Querying A records
To get a list of all the address(es) for a domain name, use the a option:

```
dig +nocmd google.com a +noall +answer

google.com.		128	IN	A	216.58.206.206
```
As you already know, if no DNS record type is specified, dig will request the A record. You can also query the A record without specifying the a option.

2. Querying CNAME records
To find the alias domain name use the cname option:

```
dig +nocmd mail.google.com cname +noall +answer

mail.google.com.	553482	IN	CNAME	googlemail.l.google.com.
```

3. Querying TXT records
Use the txt option to retrieve all the TXT records for a specific domain:

```
dig +nocmd google.com txt +noall +answer

google.com.		300	IN	TXT	"facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95"
google.com.		300	IN	TXT	"v=spf1 include:_spf.google.com ~all"
google.com.		300	IN	TXT	"docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e"
```
4. Querying MX records
To get a list of all the mail servers for a specific domain use the mx option:


```
dig +nocmd google.com mx +noall +answer

google.com.		494	IN	MX	30 alt2.aspmx.l.google.com.
google.com.		494	IN	MX	10 aspmx.l.google.com.
google.com.		494	IN	MX	40 alt3.aspmx.l.google.com.
google.com.		494	IN	MX	50 alt4.aspmx.l.google.com.
google.com.		494	IN	MX	20 alt1.aspmx.l.google.com.
```
5. Querying NS records
To find the authoritative name servers for our specific domain use the ns option:

```
dig +nocmd google.com ns +noall +answer

google.com.		84527	IN	NS	ns1.google.com.
google.com.		84527	IN	NS	ns2.google.com.
google.com.		84527	IN	NS	ns4.google.com.
google.com.		84527	IN	NS	ns3.google.com.
```

6. Querying All Records
Use the any option to get a list of all DNS records for a specific domain:

```
dig +nocmd google.com any +noall +answer

google.com.		299	IN	A	216.58.212.14
google.com.		299	IN	AAAA	2a00:1450:4017:804::200e
google.com.		21599	IN	NS	ns2.google.com.
google.com.		21599	IN	NS	ns1.google.com.
google.com.		599	IN	MX	30 alt2.aspmx.l.google.com.
google.com.		21599	IN	NS	ns4.google.com.
google.com.		599	IN	MX	50 alt4.aspmx.l.google.com.
google.com.		599	IN	MX	20 alt1.aspmx.l.google.com.
google.com.		299	IN	TXT	"docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e"
google.com.		21599	IN	CAA	0 issue "pki.goog"
google.com.		599	IN	MX	40 alt3.aspmx.l.google.com.
google.com.		3599	IN	TXT	"facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95"
google.com.		21599	IN	NS	ns3.google.com.
google.com.		599	IN	MX	10 aspmx.l.google.com.
google.com.		3599	IN	TXT	"v=spf1 include:_spf.google.com ~all"
google.com.		59	IN	SOA	ns1.google.com. dns-admin.google.com. 216967258 900 900 1800 60
```

Reverse DNS Lookup
To query the hostname associated with a specific IP address use the -x option.
For example, to perform a reverse lookup on 208.118.235.148 you would type:

```
dig -x 208.118.235.148 +noall +answer
```
As you can see from the output below the IP address 208.118.235.148 is associated with the hostname wildebeest.gnu.org.

```
; <<>> DiG 9.13.3 <<>> -x 208.118.235.148 +noall +answer
;; global options: +cmd
148.235.118.208.in-addr.arpa. 245 IN	PTR	wildebeest.gnu.org.
```

## Age

* Download and Install

```
https://github.com/FiloSottile/age
```

* Generate a New Key Par

```
mkdir ~/.age
age-keygen -o ~/.age/key.txt
```

Share the public key with recipient

* Encrypt a file with recipient's public key

```
age -r [receipient public key] example.txt > example.txt.age
```

* Decrypt a file

```
age --decrypt example.txt.age -i ~/.age/key.txt -o example.txt
```

* Encrypt & Decrypt using a passphrase

```
# encrypt
age -p secrets.txt > secrets.txt.age
Enter passphrase (leave empty to autogenerate a secure one):

# decrypt
$ age -d secrets.txt.age > secrets.txt
Enter passphrase:
```

## Asdf

* Config

```
#config.fish
3.9.19
set -gx --prepend PATH /Users/username/.asdf/shims
```

`set -x -U ASDF_DATA_DIR "/Users/username/.asdf"`


* Pyenv replacement

```
$ asdf plugin add python

$ asdf install python

$ asdf set -u python 3.9.19 This sets python 3.9.19 as our default python version

```

* Rbenv

```
$ asdf plugin add ruby

$ asdf install ruby latest # We can omit the version number. Currently installs 2.7.1

$ asdf set -u ruby 2.7.1

```

* Goenv

```
$ asdf plugin add golang

$ asdf install golang latest # 1.14.6

$ asdf set -u golang 1.14.6
```

* Nvm

```
$ asdf plugin add nodejs

$ asdf install nodejs 12.18.2

$ asdf set -u nodejs 12.18.2
```

* Asdf Global

Using asdf set -u creates a file under your HOME directory called .tool-versions. This lets asdf know which versions to use. And of course, in contrast to global, there is also the local keyword that creates another .tool-versions. This is useful when projects require different version.

```
$ cat ~/.tool-versions

python 3.8.4

ruby 2.7.1

golang 1.14.6

nodejs 12.18.2

```

## Terraform

Luckily Terraform allows for plugins caching. So, whenever plugin has to be downloaded and is present in the cache directory, it will be copied into the project instead. This can save some time and bandwidth.

```
touch ~/.terraformrc
```
Put this in your ~/.terraformrc and enjoy:

```
plugin_cache_dir   = "$HOME/.terraform.d/plugin-cache"
```
Then create the cache directory:

```
mkdir -p $HOME/.terraform.d/plugin-cache
```


## Ollama

Run a model

`ollama run llama2`

Show models

`ollama list`

Http serve

`ollama serve`

Create new model

`ollama create somename -f Modelfile`

`ollama run somename`

OpenAI compatability

To invoke Ollama’s OpenAI compatible API endpoint, use the same OpenAI format and change the hostname to http://localhost:11434:

```
curl http://localhost:11434/v1/chat/completions \
    -H "Content-Type: application/json" \
    -d '{
        "model": "llama2",
        "messages": [
            {
                "role": "system",
                "content": "You are a helpful assistant."
            },
            {
                "role": "user",
                "content": "Hello!"
            }
        ]
    }'
```

## Mise

Run a command once with a specific version

```bash
mise exec node@22 -- node -v
```

Make a version available globally

```bash
mise use --global node@lts
node -v
# v22.14.0
```

See versions installed
```bash
mise ls
Tool  Version  Source                      Requested
node  22.17.1  ~/.config/mise/config.toml  lts
```

Use mise for a specific project

```bash
cd myproj
mise use node@23
# mise node@23.10.0 ✓ installed
node -v
# v23.10.0
cat mise.toml
# [tools]
# node = "23"
```

We will leave this directory. The node version will revert to the global LTS version
```bash
cd ..
node -v
# v22.14.0
```
