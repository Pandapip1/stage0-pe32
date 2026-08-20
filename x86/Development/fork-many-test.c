/* fork and reap, many times over, watching for anything that accumulates.
 * Each turn starts a child, waits for it, and checks what it exited with; a
 * handle or a page leaked per fork would show up here as a failure partway
 * through rather than at the start. */
int main(int argc, char** argv)
{
	int pid;
	int* status;
	int i;
	int n;
	int bad;

	n = 100;
	bad = 0;
	status = calloc(1, 4);

	fputs("forking ", stdout);
	fputs(int2str(n, 10, TRUE), stdout);
	fputs(" times\n", stdout);
	fflush(stdout);

	i = 0;
	while(i < n)
	{
		pid = fork();
		if(0 > pid)
		{
			fputs("fork failed at ", stdout);
			fputs(int2str(i, 10, TRUE), stdout);
			fputs("\n", stdout);
			fflush(stdout);
			return 1;
		}
		if(0 == pid) _exit(11);
		if(0 > waitpid(pid, status, 0)) return 1;
		if(11 != (status[0] / 256)) bad = bad + 1;
		i = i + 1;
	}

	fputs("done; wrong exits = ", stdout);
	fputs(int2str(bad, 10, TRUE), stdout);
	fputs("   (expected 0)\n", stdout);
	fflush(stdout);
	if(0 != bad) return 1;
	return 0;
}
