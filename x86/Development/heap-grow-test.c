/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Additional permission under GNU GPL version 3 section 7:
 * see LICENSE.EXCEPTION in the root of this project.
 *
 * malloc(), pushed well past the image's own 128MB section, and checked
 * rather than trusted: each chunk is written at its first and last byte with
 * a pattern that depends on which chunk it is, then every earlier chunk is
 * re-read to confirm nothing was silently aliased or left unbacked.  Before
 * M2libc's own stdlib.c (a fork, https://github.com/Pandapip1/M2libc,
 * branch windows-malloc-brk -- see .gitmodules) gave _malloc_brk a
 * #ifdef __windows__ path that grows past one image-sized region into
 * further ones reserved and committed from the operating system as needed,
 * this would have failed outright once the 128MB section ran out, or --
 * from an earlier design tried and abandoned for this same fix -- failed
 * to even start, on STATUS_CONFLICTING_ADDRESSES, because nowhere fixed
 * and contiguous with the image was actually free to grow into. See
 * _malloc_brk's own comment in that fork's stdlib.c for the full mechanism
 * and why the simpler designs before it did not work.
 */

int main(int argc, char** argv)
{
	int n;
	int chunk;
	int i;
	char* p;
	char** chunks;
	int total;
	int ok;

	n = 24;              /* 24 * 12MB = ~288MB, well past the 128MB image */
	chunk = 12 * 1024 * 1024;
	chunks = calloc(n, 4);
	ok = 1;
	total = 0;

	fputs("allocating ", stdout);
	fputs(int2str(n, 10, TRUE), stdout);
	fputs(" chunks of ", stdout);
	fputs(int2str(chunk, 10, TRUE), stdout);
	fputs(" bytes\n", stdout);
	fflush(stdout);

	i = 0;
	while(i < n)
	{
		p = malloc(chunk);
		if(NULL == p)
		{
			fputs("malloc failed at chunk ", stdout);
			fputs(int2str(i, 10, TRUE), stdout);
			fputs("\n", stdout);
			fflush(stdout);
			ok = 0;
			break;
		}
		chunks[i] = p;

		/* A pattern that depends on which chunk this is, so a later chunk
		 * aliasing an earlier one's address is not mistaken for success. */
		p[0] = 65 + (i % 26);            /* 'A'.. */
		p[chunk - 1] = 97 + (i % 26);     /* 'a'.. */

		total = total + chunk;
		i = i + 1;
	}

	fputs("allocated ", stdout);
	fputs(int2str(total, 10, TRUE), stdout);
	fputs(" bytes across ", stdout);
	fputs(int2str(i, 10, TRUE), stdout);
	fputs(" chunks\n", stdout);
	fflush(stdout);

	/* Re-read every chunk actually allocated, checking both ends, so a chunk
	 * silently unbacked or overwritten by a later one is caught here rather
	 * than only by the write above happening not to fault. */
	n = i;
	i = 0;
	while(i < n)
	{
		p = chunks[i];
		if((65 + (i % 26)) != p[0])
		{
			fputs("MISMATCH at start of chunk ", stdout);
			fputs(int2str(i, 10, TRUE), stdout);
			fputs("\n", stdout);
			fflush(stdout);
			ok = 0;
		}
		if((97 + (i % 26)) != p[chunk - 1])
		{
			fputs("MISMATCH at end of chunk ", stdout);
			fputs(int2str(i, 10, TRUE), stdout);
			fputs("\n", stdout);
			fflush(stdout);
			ok = 0;
		}
		i = i + 1;
	}

	if(ok) fputs("ALL CHUNKS OK\n", stdout);
	else fputs("FAILED\n", stdout);
	fflush(stdout);
	if(0 == ok) return 1;
	return 0;
}
