#include "../include/ftrace_manager.h"

int resolve_hook_address (struct ftrace_hook *hook){
        hook->address = kallsyms_lookup_name(hook->name);
        if (!hook->address) {
                printk(KERN_DEBUG "KOOPA:: Unresolved symbol on resolve_hook_address(): %s\n", hook->name);
                return -ENOENT;
        }
        *((unsigned long*) hook->original) = hook->address;
        return 0;
}


void notrace ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs){
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    if (!within_module(parent_ip, THIS_MODULE)){
		regs->ip = (unsigned long) hook->function;
	}
    printk(KERN_INFO "KOOPA:: THUNK\n");
		
}


int install_hook(struct ftrace_hook *hook){
    int err;
    printk(KERN_INFO "KOOPA:: Installing hook %s\n", hook->name);
    err = resolve_hook_address(hook);
    if(err){
		printk(KERN_DEBUG "KOOPA:: Could not resolve the hook address on install_hook()\n");
		return err;
	}
      
    hook->ops.func = ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS| FTRACE_OPS_FL_RECURSION_SAFE| FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if(err){
        printk(KERN_DEBUG "KOOPA:: ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }
        
	err = register_ftrace_function(&hook->ops);
    if(err){
        printk(KERN_DEBUG "KOOPA:: register_ftrace_function() failed: %d\n", err);
        return err;
    }

    printk(KERN_DEBUG "KOOPA:: hook loaded: %s\n", hook->name);
    return 0;
}


void remove_hook(struct ftrace_hook *hook){
    int err = unregister_ftrace_function(&hook->ops);
    if(err){
        printk(KERN_DEBUG "KOOPA:: unregister_ftrace_function() failed: %d\n", err);
    }
	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if(err){
        printk(KERN_DEBUG "KOOPA:: ftrace_set_filter_ip() failed: %d\n", err);
    }
}

int install_hooks_set(struct ftrace_hook *hooks, size_t count){
    int ii;
    for (ii=0; ii<count; ii++){
        int err = install_hook(&hooks[ii]);
        if(err){
            while (ii!=0){
                remove_hook(&hooks[--ii]);
            }
            return err;
        }
            
    }
    return 0;    
}

void remove_hooks_set(struct ftrace_hook *hooks, size_t count){
    int ii;
    for (ii=0; ii<count; ii++){
        remove_hook(&hooks[ii]);
    }
        
}
