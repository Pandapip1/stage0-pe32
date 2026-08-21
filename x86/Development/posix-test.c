/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Additional permission under GNU GPL version 3 section 7:
 * see LICENSE.EXCEPTION in the root of this project.
 *
 * Every routine M2libc/x86/windows/ provides, called once, with the answer
 * checked.  Build it the way Phase 7 builds hex2 -- the same -f list, with
 * this file last instead of hex2's -- and run it with any existing file as
 * argv[1].  It makes and removes posixtest-dir in the working directory.
 *
 * The ones expected to fail are as much the point as the ones expected to
 * work: chroot, mount, unshare, symlink, mknod and fchdir have no Windows
 * answer, and this checks that they say so rather than quietly returning 0.
 */


int failures;

void ok(char* what, int got, int want)
{
	fputs(what, stdout);
	fputs(": got ", stdout);
	fputs(int2str(got, 10, TRUE), stdout);
	if(got == want) fputs("  ok\n", stdout);
	else
	{
		fputs("  WANTED ", stdout);
		fputs(int2str(want, 10, TRUE), stdout);
		fputs("\n", stdout);
		failures = failures + 1;
	}
}

void show(char* what, char* s)
{
	fputs(what, stdout);
	fputs(": ", stdout);
	fputs(s, stdout);
	fputs("\n", stdout);
}

int main(int argc, char** argv)
{
	struct utsname* u;
	char* cwd;
	int fd;

	failures = 0;

	/* access: this file's own directory is there, and a made-up name is not */
	ok("access(argv[1], F_OK)", access(argv[1], F_OK), 0);
	ok("access(argv[1], R_OK)", access(argv[1], R_OK), 0);
	ok("access(no such, F_OK)", access("no-such-file-anywhere", F_OK), -1);

	/* getcwd, then chdir up and back */
	cwd = get_current_dir_name();
	if(NULL == cwd)
	{
		fputs("get_current_dir_name: NULL\n", stdout);
		failures = failures + 1;
	}
	else show("cwd", cwd);

	ok("chdir(\"..\")", chdir(".."), 0);
	show("cwd after chdir", get_current_dir_name());
	ok("chdir(back)", chdir(cwd), 0);
	show("cwd after chdir back", get_current_dir_name());
	ok("chdir(no such)", chdir("no-such-directory-anywhere"), -1);

	/* mkdir, then a file in it, then unlink both ways round */
	ok("mkdir", mkdir("posixtest-dir", 0755), 0);
	ok("mkdir again", mkdir("posixtest-dir", 0755), -1);
	ok("access(the new dir)", access("posixtest-dir", F_OK), 0);

	fd = open("posixtest-dir/f", 577, 0644);   /* O_WRONLY|O_CREAT|O_TRUNC */
	if(0 == fd)
	{
		fputs("open in the new dir failed\n", stdout);
		failures = failures + 1;
	}
	else
	{
		write(fd, "hello", 5);
		close(fd);
		ok("access(the new file)", access("posixtest-dir/f", F_OK), 0);
		ok("unlink(the new file)", unlink("posixtest-dir/f"), 0);
		ok("access(it again)", access("posixtest-dir/f", F_OK), -1);
	}
	ok("unlink(the dir)", unlink("posixtest-dir"), 0);
	ok("unlink(no such)", unlink("no-such-file-anywhere"), -1);

	/* uname */
	u = calloc(1, sizeof(struct utsname));
	if(0 != uname(u))
	{
		fputs("uname failed\n", stdout);
		failures = failures + 1;
	}
	else
	{
		show("sysname", u->sysname);
		show("release", u->release);
		show("version", u->version);
		show("machine", u->machine);
	}

	/* the ones that keep a number or answer a constant */
	ok("umask(022)", umask(18), 0);
	ok("umask(0) gives back 022", umask(0), 18);
	ok("geteuid", geteuid(), 0);
	ok("getegid", getegid(), 0);
	ok("chmod", chmod(argv[1], 0755), 0);
	ok("fchmod", fchmod(0, 0755), 0);

	/* the ones with no Windows answer, which must fail rather than lie */
	ok("fchdir", fchdir(0), -1);
	ok("symlink", symlink("a", "b"), -1);
	ok("mknod", mknod("a", 0, 0), -1);
	ok("chroot", chroot("/"), -1);
	ok("unshare", unshare(0), -1);
	ok("mount", mount("a", "b", "c", 0, 0), -1);

	fputs("\n", stdout);
	if(0 == failures) fputs("all ok\n", stdout);
	else
	{
		fputs(int2str(failures, 10, TRUE), stdout);
		fputs(" FAILURES\n", stdout);
	}
	return failures;
}
