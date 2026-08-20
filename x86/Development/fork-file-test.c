/* Does an open file survive fork?  POSIX says a child gets its parent's
 * descriptors; this checks that one opened before the fork still writes to the
 * same file, from the child, under the same number. */
int main(int argc, char** argv)
{
	int fd;
	int pid;
	int* status;
	char* buf;
	int n;

	status = calloc(1, 4);

	fd = open("forkfile.txt", 577, 0644);   /* O_WRONLY|O_CREAT|O_TRUNC */
	if(0 > fd) { fputs("open failed\n", stdout); fflush(stdout); return 1; }

	write(fd, "parent-before\n", 14);

	pid = fork();
	if(0 > pid) { fputs("fork failed\n", stdout); fflush(stdout); return 1; }
	if(0 == pid)
	{
		write(fd, "child-wrote\n", 12);
		_exit(0);
	}
	waitpid(pid, status, 0);

	write(fd, "parent-after\n", 13);
	close(fd);

	fd = open("forkfile.txt", 0, 0);
	if(0 > fd) { fputs("reopen failed\n", stdout); fflush(stdout); return 1; }
	buf = calloc(256, 1);
	n = read(fd, buf, 255);
	close(fd);
	fputs("file now holds:\n", stdout);
	fputs(buf, stdout);
	fputs("(child-wrote present above means the fd survived fork)\n", stdout);
	fflush(stdout);
	return 0;
}
