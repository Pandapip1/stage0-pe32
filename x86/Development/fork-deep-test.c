/* fork from the bottom of a deep call chain.
 *
 * The parent's committed stack grows as it recurses; a freshly started child
 * has barely touched its own.  If fork copies the parent's whole committed
 * stack into pages the child has not committed, the write fails and takes the
 * fork with it -- so this is the shape of the failure to watch for. */

int depth_reached;

/* More frames, used by the child after the fork. */
int deeper(int n)
{
	int pad;
	pad = n;
	if(n > 0)
	{
		if(0 != deeper(n - 1)) return 1;
		if(pad != n) return 1;
	}
	return 0;
}

int recurse(int n)
{
	int pad;
	int pid;
	int* status;
	int r;

	pad = n;
	if(n > 0)
	{
		r = recurse(n - 1);
		if(pad != n) return -99;   /* our frame survived the call below */
		return r;
	}

	depth_reached = 1;
	status = calloc(1, 4);
	pid = fork();
	if(0 > pid) return -1;
	if(0 == pid)
	{
		/* The child goes deeper still, from the stack it inherited.  Its own
		 * TEB says less of that stack is committed than now is, so this is
		 * where a stack that fork left inconsistent would show it. */
		if(0 != deeper(300)) _exit(44);
		_exit(33);
	}
	if(0 > waitpid(pid, status, 0)) return -2;
	return status[0] / 256;
}

int main(int argc, char** argv)
{
	int r;
	int d;

	d = 400;
	fputs("forking from ", stdout);
	fputs(int2str(d, 10, TRUE), stdout);
	fputs(" frames deep\n", stdout);
	fflush(stdout);

	r = recurse(d);

	fputs("result = ", stdout);
	fputs(int2str(r, 10, TRUE), stdout);
	fputs("   (expected 33)\n", stdout);
	fflush(stdout);
	if(33 != r) return 1;
	return 0;
}
