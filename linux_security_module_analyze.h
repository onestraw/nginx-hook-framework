////////////////////////////////////////////////////////////////////////////////
//  1. check where the hooks is called
////////////////////////////////////////////////////////////////////////////////
// fs/open.c
static int do_dentry_open(struct file *f,
			  struct inode *inode,
			  int (*open)(struct inode *, struct file *),
			  const struct cred *cred)
{
    //...
	error = security_file_open(f, cred);
    //...
}


int security_file_open(struct file *file, const struct cred *cred)
{
	int ret;

	ret = call_int_hook(file_open, 0, file, cred);
	if (ret)
		return ret;

	return fsnotify_perm(file, MAY_OPEN);
}
/*
 * Hook list operation macros.
 *
 * call_void_hook:
 *	This is a hook that does not return a value.
 *
 * call_int_hook:
 *	This is a hook that returns a value.
 */

#define call_void_hook(FUNC, ...)				\
	do {							\
		struct security_hook_list *P;			\
								\
		list_for_each_entry(P, &security_hook_heads.FUNC, list)	\
			P->hook.FUNC(__VA_ARGS__);		\
	} while (0)

#define call_int_hook(FUNC, IRC, ...) ({			\
	int RC = IRC;						\
	do {							\
		struct security_hook_list *P;			\
								\
		list_for_each_entry(P, &security_hook_heads.FUNC, list) { \
			RC = P->hook.FUNC(__VA_ARGS__);		\
			if (RC != 0)				\
				break;				\
		}						\
	} while (0);						\
	RC;							\
})

////////////////////////////////////////////////////////////////////////////////
//  2. how to add hook to security_hook_heads
//     take capability as an example
////////////////////////////////////////////////////////////////////////////////

struct security_hook_heads {
	struct list_head capable;
	struct list_head settime;
    //....
	struct list_head vm_enough_memory;
} __randomize_layout;

/*
 * Security module hook list structure.
 * For use with generic list macros for common operations.
 */
struct security_hook_list {
	struct list_head		list;
	struct list_head		*head;
	union security_list_options	hook;
	char				*lsm;
} __randomize_layout;


/*
 * Initializing a security_hook_list structure takes
 * up a lot of space in a source file. This macro takes
 * care of the common case and reduces the amount of
 * text involved.
 */
#define LSM_HOOK_INIT(HEAD, HOOK) \
	{ .head = &security_hook_heads.HEAD, .hook = { .HEAD = HOOK } }

extern struct security_hook_heads security_hook_heads;


struct security_hook_list capability_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(capable, cap_capable),
	LSM_HOOK_INIT(settime, cap_settime),
	//...
	LSM_HOOK_INIT(vm_enough_memory, cap_vm_enough_memory),
};
//LSM_HOOK_INIT second argument is inserting hook function

void __init capability_add_hooks(void)
{
	security_add_hooks(capability_hooks, ARRAY_SIZE(capability_hooks),
				"capability");
}

/**
 * security_add_hooks - Add a modules hooks to the hook lists.
 * @hooks: the hooks to add
 * @count: the number of hooks to add
 * @lsm: the name of the security module
 *
 * Each LSM has to register its hooks with the infrastructure.
 */
void __init security_add_hooks(struct security_hook_list *hooks, int count,
				char *lsm)
{
	int i;

	for (i = 0; i < count; i++) {
		hooks[i].lsm = lsm;
		list_add_tail_rcu(&hooks[i].list, hooks[i].head);
	}
	if (lsm_append(lsm, &lsm_names) < 0)
		panic("%s - Cannot get early memory.\n", __func__);
}

////////////////////////////////////////////////////////////////////////////////
//  3. security point in kernel struct
//     Q: how to handle several security module use the same *security?
//     A: linux does not handle the case.
////////////////////////////////////////////////////////////////////////////////

struct file {
#ifdef CONFIG_SECURITY
	void			*f_security;
#endif
};

//allocate and assign f_security in int file_alloc_security(struct file *file){}

struct inode {
#ifdef CONFIG_SECURITY
	void			*i_security;
#endif
};

//allocate and assign i_security in int inode_alloc_security(struct inode *inode)
