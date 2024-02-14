int pipe(int __user *fildes);
int pipe2(int __user *fildes, int flags);
int close(unsigned int fd);

/* __ARCH_WANT_SYSCALL_NO_FLAGS */
asmlinkage long sys_pipe(int __user *fildes);
/* fs/pipe.c */
asmlinkage long sys_pipe2(int __user *fildes, int flags);

asmlinkage long sys_close(unsigned int fd);
asmlinkage long sys_close_range(unsigned int fd, unsigned int max_fd,
				unsigned int flags);

/*
 * Careful here! We test whether the file pointer is NULL before
 * releasing the fd. This ensures that one clone task can't release
 * an fd while another clone is opening it.
 */
SYSCALL_DEFINE1(close, unsigned int, fd)
{
	int retval = close_fd(fd);

	/* can't restart close syscall because file table entry was cleared */
	if (unlikely(retval == -ERESTARTSYS ||
		     retval == -ERESTARTNOINTR ||
		     retval == -ERESTARTNOHAND ||
		     retval == -ERESTART_RESTARTBLOCK))
		retval = -EINTR;

	return retval;
}

int close_fd(unsigned fd)
{
	struct files_struct *files = current->files;
	struct file *file;

	spin_lock(&files->file_lock);
	file = pick_file(files, fd);
	spin_unlock(&files->file_lock);
	if (!file)
		return -EBADF;

	return filp_close(file, files);
}

SYSCALL_DEFINE2(pipe2, int __user *, fildes, int, flags)
{
	return do_pipe2(fildes, flags);
}

SYSCALL_DEFINE1(pipe, int __user *, fildes)
{
	return do_pipe2(fildes, 0);
}

/*
 * sys_pipe() is the normal C calling standard for creating
 * a pipe. It's not the way Unix traditionally does this, though.
 */
static int do_pipe2(int __user *fildes, int flags)
{
	struct file *files[2];
	int fd[2];
	int error;

	error = __do_pipe_flags(fd, files, flags);
	if (!error) {
		if (unlikely(copy_to_user(fildes, fd, sizeof(fd)))) {
			fput(files[0]);
			fput(files[1]);
			put_unused_fd(fd[0]);
			put_unused_fd(fd[1]);
			error = -EFAULT;
		} else {
			fd_install(fd[0], files[0]);
			fd_install(fd[1], files[1]);
		}
	}
	return error;
}