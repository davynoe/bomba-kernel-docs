# Bomba Kernel Docs

Learn how to compile your own customized linux kernel like a chad<br>

Add your own system calls to the linux kernel

### Summary
- Get linux kernel source code
- Edit it to your liking
- Compile
- Install to system
- Boot using your new kernel

## 1. Install the dependencies

You can't compile the kernel without these packages, get required packages by your distro:

```sh
# For Fedora
sudo dnf install gcc flex make bison openssl-devel elfutils-libelf-devel dwarves openssl

# For Debian
sudo apt install build-essential libncurses-dev libssl-dev libelf-dev libbpf-dev bc flex bison dwarves dpkg-dev
```

## 2. Get the linux kernel source

### For Debian

Because your kernel is quite old, you want to run apt's built in command to get the source version that is close to your current kernel's version

```sh
apt source linux-source
```

### For Fedora

Because your kernel is really up to date, you can get the latest stable tarball from [The Linux Kernel Archives](https://kernel.org/)
After downloading the tarball, extract it

```sh
tar -xvf linux-{version}.tar.gz
``` 

## 3. Configure the kernel

Go to the source directory you extracted

```sh
cd linux-{version}/
```

For most of the time you want to stick to your current kernel's exact same config. So generate a config based on your system's config:

```sh
make olddefconfig
```

This will create `.config` file which is your kernels config, and apply settings that your systems kernel has. 

### Adding our custom version name to the kernel

You can skip this step since it's unnecessary, but its cool to be able to name your kernel.
Let's add our custom version name to this kernel. Edit the kernel with your favourite text editor

```sh
vim .config
```

Set the line `CONFIG_LOCALVERSION="-bomba"`. The final kernel's name will be like: linux.{version}-bomba

## 4. Define your system calls

You must first define your system calls in `kernel/sys.c`. It could be any .c file in kernel/ but its a good approach to pick sys.c out of all of them. 

Append these lines to the end of `kernel/sys.c`:

```c
/* by bomba kernel */
SYSCALL_DEFINE0(bomba)
{
    pr_info("Bomba was called!\n");
    return 0;
}

/* needed for get_proc_state_string */
static const char * const task_state_array[] = {
    /* states in TASK_REPORT: */
    "R (running)",     /* 0x00 */
    "S (sleeping)",    /* 0x01 */
    "D (disk sleep)",  /* 0x02 */
    "T (stopped)",     /* 0x04 */
    "t (tracing stop)",/* 0x08 */
    "X (dead)",        /* 0x10 */
    "Z (zombie)",      /* 0x20 */
    "P (parked)",      /* 0x40 */
    /* states beyond TASK_REPORT: */
    "I (idle)",        /* 0x80 */
};

SYSCALL_DEFINE2(set_proc_state, pid_t, pid, int, state)
{
    struct task_struct *task;

    if (pid == 0) {
        set_current_state(state);
        schedule();
        return 0;
    }

    for_each_process(task) {
        if (task->pid == pid) {
            task->__state = state;
            return 0;
        }
    }

    return -ESRCH;
}

SYSCALL_DEFINE1(get_proc_state, pid_t, pid)
{
    struct task_struct *task;

    if (pid == 0)
        return get_current_state();

    for_each_process(task) {
        if (task->pid == pid)
            return task->__state;
    }

    return -ESRCH;
}

SYSCALL_DEFINE3(get_proc_state_string, pid_t, pid, void *, buf, size_t, size)
{
    struct task_struct *task;
    const char *state_str;
    char kbuf[16];  /* string kopyası için geçici buffer */

    if (pid == 0)
        task = current;
    else {
        task = pid_task(find_vpid(pid), PIDTYPE_PID);
        if (!task)
            return -ESRCH;
    }

    state_str = task_state_array[task_state_index(task)];
    strncpy(kbuf, state_str, sizeof(kbuf));

    if (copy_to_user(buf, kbuf, strnlen(kbuf, size)))
        return -EFAULT;

    return 0;
}
```

## 5. Add system call definitions to headers

Now we have to add these definitions to syscall definition headers.

The system call definition headers are located at `include/linux/syscalls.h`

Add these prototypes below `asmlinkage long sys_vfork(void)` line in `include/linux/syscalls.h`:

```c
/* syscalls by bomba kernel */
asmlinkage long sys_bomba(void);
asmlinkage long sys_set_proc_state(pid_t pid, int state);
asmlinkage long sys_get_proc_state(pid_t pid);
asmlinkage long sys_get_proc_state_string(pid_t pid, void *buf, size_t size);
```

## 6. Add your system calls to the system call table

In order to be able to call these syscalls we need to assign them a number at the system call table for the corresponding cpu architecture we work for.

Most of us use x86_64 machines, therefore we need to add these syscalls to the x86_64 system call table.

The system call table for x86_64 architecture is located at `arch/x86/entry/syscalls/syscall_64.tbl`

Append these lines to the end of `arch/x86/entry/syscalls/syscall64.tbl`:

```
# added by bomba kernel
548    common    bomba            sys_bomba
549    common    set_proc_state        sys_set_proc_state
550    common    get_proc_state        sys_get_proc_state
551    common    get_proc_state_string    sys_get_proc_state_string
``` 
> Assuming the last syscall number in the file was 547.

## 7. Compile the kernel

All the configuration and additions we made are done at this point so all we have to do is to build this customized kernel. Since we are gonna be building the entire kernel from source, its gonna take some time. **A better cpu with more cores is recommended.**

Roughly this process is gonna take around 1+ hours, Time changing factor will be your cpu's computational power and the number of cores it has.

Also make sure your machine **at least has 4 GBs of RAM**, because you might run out of memory while compiling otherwise.

When you are ready, run these commands:

```sh
# Build the kernel (use all available cpu cores)
make -j$(nproc)

# Build modules
sudo make -j$(nproc) modules_install

# Install the kernel to the system and to the boot menu
sudo make install
```

> `nproc` command returns the number of cores you have on your system.<br>

> You can change make -j$(nproc) as **`make -jN`**, replace N with the number of cores you want to use.

## 8. Reboot

You can reboot and pick the desired kernel on the boot menu's advanced settings. But you dont need to do that since your default kernel will be set as your own customized kernel after the make install. Just reboot.

After rebooting you can check your kernel's version to verify you've succeeded:

```sh
# Get current kernel name and version
uname -r

# Get boot/kernel logs
sudo dmesg | grep "Linux"

# List boot files, (has your config and stuff related to your kernel)
ls /boot
```

## 9. Test the system calls

To verify our system calls are working, we must call them. We are gonna use C to test our system calls.

### Test programs in C

- bomba.c

```c
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#define __NR_bomba 548

int main() { 
	long result = syscall(__NR_bomba); 
	if(result == -1) perror("Syscall failed");
	else printf("Bomba was called, result:%ld\n",result); 
	return 0; 
}
``` 
<br>

- test_get_state.c

```c
#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <stdio.h>
#define __NR_get_proc_state 550

int main(int argc, char *argv[]) {
    pid_t pid = atoi(argv[1]);
    long state = syscall(__NR_get_proc_state, pid);

    if (state >= 0) {
        printf("Process state: 0x%lx\n", state);
    } else {
        perror("Error getting process state");
    }

    return 0;
}
```
<br>

- test_set_state.c

```c
#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <stdio.h>
#define __NR_set_proc_state 549

int main(int argc, char *argv[]) {
    pid_t pid = atoi(argv[1]);
    int state = atoi(argv[2]);

    long result = syscall(__NR_set_proc_state, pid, state);

    if (result == 0) {
        printf("Process state changed successfully.\n");
    } else {
        perror("Error changing process state");
    }

    return 0;
}
```

### Testing

Printing our bomba log to kernel:

```sh
# Compile and run
gcc bomba.c -o bomba;./bomba

# Check kernel logs (we should see our bomba syscall print)
sudo dmesg | tail -10
```
<br>

Getting a process' state:

```sh
# Open firefox
firefox &

# Get PID of firefox
ps aux | grep firefox

# Returns a hexadecimal number, for process state (0x01: Sleeping, 0x00: Running etc.)
./test_get_state PID_OF_FIREFOX

# Get detailed status of the process, compare if state matches with our program
cat /proc/PID_OF_FIREFOX/status
```
<br>

Setting a process' state:

```sh
# Open firefox
firefox &

# Get PID of firefox
ps aux | grep firefox

# Check state of firefox
cat /proc/PID_OF_FIREFOX/status

# Change firefox's state with our program
# NN, 2 digit number for process state, 00: Sleeping, 01: Running etc.
./test_set_state PID_OF_FIREFOX NN

# Check if state of firefox is changed
cat /proc/PID_OF_FIREFOX/status
```
