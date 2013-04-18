/*
 * Copyright (C) 2013 Canonical
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.   
 *  
 */ 

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <signal.h>
#include <errno.h>

#define APP_NAME		"nexus4-gpustat"
#define OPT_QUIET		(0x00000001)

#define T_STATE_START		0x00000001
#define T_STATE_SUBMIT		0x00000002
#define T_STATE_RB_SUBMIT	0x00000003
#define T_STATE_IDLE		0x00000004
#define T_STATE_IRQ		0x00000005

static volatile bool stop_gpustat = false; 	/* Stops gpustat main loop */
static volatile bool stop_gputrace = false; 	/* Stops tracing main loop */

static pid_t trace_pid;				/* PID of tracer process */

typedef struct {
	unsigned long long on_time;		/* usec GPU on time */
	unsigned long long elapsed_time;	/* usec GPU elapsed time */
	unsigned long long pwr_level[5];	/* usec GPU at power levels 1..5 */
} gputop_info;

typedef struct gpu_submit_procs {
	char *task;				/* Name of process submitting GPU action */
	unsigned long count;			/* Number of times process has submitted */
	struct gpu_submit_procs *next;		/* Next one in list */
} gpu_submit_procs;


/*
 *  handle_sigint
 *	catch SIGINT, flag to stop main loop
 */
static void handle_sigint(int dummy)
{
        (void)dummy;
	stop_gpustat = true;
}

/*
 *   get_uptime
 *	fetch system uptime in seconds
 */
static int get_uptime(float *uptime)
{
	FILE *fp;
	int ret = 0;

	*uptime = 0.0;

	fp = fopen("/proc/uptime", "r");
	if (fp == NULL) {
		fprintf(stderr, "Cannot open /proc/uptime\n");
		return -1;
	}

	if (fscanf(fp, "%f", uptime))
		ret = -1;

	fclose(fp);

	return ret;
}

/*
 *  nexus4_get_gputop
 *	read GPU top values, values in uS
 */
static int nexus4_get_gputop(gputop_info *info)
{
	FILE *fp;
	int ret = 0;

	fp = fopen("/sys/devices/platform/kgsl-3d0.0/kgsl/kgsl-3d0/gputop", "r");
	if (fp == NULL)
		return -1;

	if (fscanf(fp, "%llu %llu %llu %llu %llu %llu %llu\n",
		&info->on_time,
		&info->elapsed_time,
		&info->pwr_level[0],
		&info->pwr_level[1],
		&info->pwr_level[2],
		&info->pwr_level[3],
		&info->pwr_level[4]) != 7)
		ret = -1;

	fclose(fp);

	return ret;
}

/*
 *  nexus4_get_gpuclk
 *	get GPU clk info, values in Hz
 */
static int nexus4_get_gpuclk(unsigned long long *clk)
{
	FILE *fp;
	int ret = 0;

	fp = fopen("/sys/devices/platform/kgsl-3d0.0/kgsl/kgsl-3d0/gpuclk", "r");
	if (fp == NULL)
		return -1;

	if (fscanf(fp, "%llu\n", clk) != 1)
		ret = -1;

	fclose(fp);

	return ret;
}

/*
 *  tracing_error
 *	something failed, is debugfs mounted?
 */
static void tracing_error(void)
{
	fprintf(stderr, "Kernel tracing must be enabled and debugfs mounted. To mount, use:\n");
	fprintf(stderr, "  sudo mount -t debugfs none /sys/kernel/debug\n");
}

/*
 *  handle_siguser1
 *	catch SIGUSR1 from parent and break out of tracing loop
 */
static void handle_sigusr1(int dummy)
{
        (void)dummy;
	stop_gputrace = true;
}

/*
 *  gpu_cmp
 *	for sorting GPU procs by submit count
 */
static int gpu_cmp(const void *v1, const void *v2)
{
	gpu_submit_procs **p1 = (gpu_submit_procs**)v1;
	gpu_submit_procs **p2 = (gpu_submit_procs**)v2;

	return (*p2)->count - (*p1)->count;
}

/*
 *  tracing_write
 *	update ftrace settings helper function
 */
static int tracing_write(const char *file, const char *data)
{
	FILE *fp;
	size_t n = strlen(data);
	int ret = 0;

	fp = fopen(file, "w");
	if (fp == NULL) {
		fprintf(stderr, "Cannot open tracing file %s to update\n", file);
		return -1;
	}

	if (fwrite(data, 1, n, fp) != n) {
		fprintf(stderr, "Cannot write %s to tracing file %s\n", data, file);
		ret = -1;
	}

	fclose(fp);

	return ret;
}

/*
 *  gpu_trace_start
 *	start child process to gather ftrace data
 */
static int gpu_trace_start(const char *trace_filename)
{
	pid_t pid;
	unsigned int state, last_state = 0;
	float uptime;
	FILE *fp;
	FILE *trace;
	int submitters = 0;
	int i;

	gpu_submit_procs *p, *procs = NULL, **sorted;


	if (tracing_write("/sys/kernel/debug/tracing/current_tracer", "function\n") < 0) {
		tracing_error();
		return -1;
	}

	if (tracing_write("/sys/kernel/debug/tracing/set_ftrace_filter", "adreno_*") < 0) {
		tracing_error();
		return -1;
	}

	if (tracing_write("/sys/kernel/debug/tracing/tracing_on", "1\n") < 0) {
		tracing_error();
		return -1;
	}

	fp = fopen("/sys/kernel/debug/tracing/trace_pipe", "r");
	if (fp == NULL) {
		fprintf(stderr, "Cannot open trace_pipe, kernel tracing must be enabled and debugfs mounted. to mount, use:\n");
		tracing_error();
		return -1;
	}

	trace = fopen(trace_filename, "w");
	if (fp == NULL) {
		fclose(fp);
		fprintf(stderr, "Cannot open trace file %s\n", trace_filename);
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "Failed to fork off tracing child process\n");
		fclose(fp);
		fclose(trace);
		return -1;
	}

	if (pid > 0) {
		/* Parent */
		fclose(fp);
		fclose(trace);

		trace_pid = pid;
		return 0;
	}

	/* Child */
	signal(SIGUSR1, &handle_sigusr1);
	signal(SIGINT, &handle_sigusr1);

	fprintf(trace, "    When     Process                  Kernel Function\n");
	get_uptime(&uptime);

	while (!stop_gputrace) {
		char buffer[8192];
		char *task;
		char *func;
		char *ptr;
		float when;

		if (fgets(buffer, sizeof(buffer), fp) == NULL) {
			if (errno == EINTR) {
				break;	/* No special handling? */
			}
			break;
		}
	
		buffer[sizeof(buffer)-1] = '\0';
		if (strlen(buffer) < 48)
			continue;

		sscanf(buffer + 33, "%g", &when);
		if ((when - uptime) < 0.0)
			continue;

		func = ptr = buffer + 48;
		while (*ptr && *ptr != ' ')
			ptr++;
		*ptr = '\0';

		if (strcmp(func, "adreno_start") == 0)
			state = T_STATE_START;

		if (strcmp(func, "adreno_idle") == 0)
			state = T_STATE_IDLE;

		if (strcmp(func, "adreno_irq_handler") == 0)
			state = T_STATE_IRQ;
	
		if (strcmp(func, "adreno_submit") == 0)
			state = T_STATE_SUBMIT;

		if (strcmp(func, "adreno_ringbuffer_submit") == 0)
			state = T_STATE_RB_SUBMIT;

		if (state != last_state) {
			bool found = false;
			buffer[22] = '\0';

			task = buffer;
			while (*task == ' ')
				task++;

			fprintf(trace, "%10.6f %-26.26s %s\n", when - uptime, task, func);
			last_state = state;

			/*
			 *  Keep tally of processes that are submitting to GPU
			 */
			if (state == T_STATE_SUBMIT || state == T_STATE_RB_SUBMIT) {
				for (p = procs; p; p = p->next) {
					if (strcmp(p->task, task) == 0) {
						found = true;
						p->count++;
						break;
					}
				}
				
				/*
				 *  Not found, add, don't break if out of memory 
				 */
				if (!found) {
					p = calloc(1, sizeof(*p));
					if (p != NULL) {
						p->task = strdup(task);
						if (p->task != NULL) {
							p->count = 1;
							p->next = procs;
							procs = p;
							submitters++;
						}
					}
				}
			}
		}
	}
	fclose(fp);
	
	/*
	 *  Dump out submitters sorted on submit count first order
	 */
	if (submitters) {
		sorted = calloc(submitters, sizeof(gpu_submit_procs *));
		if (!sorted) {
			printf("Cannot sort, out of memory!\n");
			exit(0);
		}

		for (p = procs, i = 0; p; p = p->next)
			sorted[i++] = p;

		qsort(sorted, submitters, sizeof(gpu_submit_procs *), gpu_cmp);

		fprintf(trace, "\nProcess                 Submit Count\n");
		for (i = 0; i < submitters; i++)
			fprintf(trace, "%-26.26s %6lu\n", sorted[i]->task, sorted[i]->count);
		free(sorted);
	}
	fclose(trace);

	for (p = procs; p; ) {
		gpu_submit_procs *next = p->next;

		free(p->task);
		free(p);
		p = next;
	}
	
	exit(0);
}

/*
 *  gpu_trace_finish
 *	kill tracing process
 */
static int gpu_trace_finish(void)
{
	int status;

	if (trace_pid > 0) {
		kill(trace_pid, SIGUSR1);
		waitpid(trace_pid, &status, 0);
		trace_pid = 0;
	}

	(void)tracing_write("/sys/kernel/debug/tracing/tracing_on", "0\n");
	(void)tracing_write("/sys/kernel/debug/tracing/set_ftrace_filter", "");

	return 0;
}


static void show_usage(void)
{
	printf("%s, version %s\n\n", APP_NAME, VERSION);
	printf("Usage %s [options] [duration] [count]\n", APP_NAME);
	printf("Options are:\n");
	printf("  -h\t\tprint this help.\n");
	printf("  -q\t\trun quietly, useful with option -r.\n");
	printf("  -r filename\tspecifies a comma separated values (CSV) output file to dump samples into.\n");
	printf("  -t filename\tUse kernel tracing (requires debugfs and ftrace enabled).\n");
}

int main(int argc, char **argv)
{
	struct timeval tv1, tv2;
	int count = 10;
	double duration = 1.0;
	double whence = 0;
	bool forever = true;
	int ret = EXIT_SUCCESS;
	int opt_flags = 0;
	char *csv_filename = NULL;
	FILE *csv = NULL;
	char *trace_filename = NULL;
	FILE *trace = NULL;

	for (;;) {
		int c = getopt(argc, argv, "hqr:t:");
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			show_usage();
			exit(EXIT_SUCCESS);
		case 'q':
			opt_flags |= OPT_QUIET;
			break;
		case 'r':
			csv_filename = optarg;
			break;
		case 't':
			trace_filename = optarg;
			break;
		}
	}

	if (optind < argc) {
		duration = atof(argv[optind++]);
		if (duration < 0.001) {
			fprintf(stderr, "Duration must be > 0.001\n");
			exit(EXIT_FAILURE);
		}
	}

	if (optind < argc) {
		forever = false;
		count = atoi(argv[optind++]);
		if (count < 1) {
			fprintf(stderr, "Count must be > 0\n");
			exit(EXIT_FAILURE);
		}
	}

	if (geteuid() != 0) {
		fprintf(stderr, "Need root privileges to run this command.\n");
		exit(EXIT_FAILURE);
	}

	if (csv_filename) {
		csv = fopen(csv_filename, "w");
		if (csv == NULL) {
			fprintf(stderr, "Cannot open CSV results file %s for writing.\n", csv_filename);
			ret = EXIT_FAILURE;
			goto tidy;
		}
	}

	if (trace_filename) {
		if (gpu_trace_start(trace_filename) < 0) {
			ret = EXIT_FAILURE;
			goto tidy;
		}
	}

	if (csv)
		fprintf(csv, "When,Freq (MHz),Elapsed,On Time,PWR L1,PWR L2,PWR L3,PWR L4,PWR L5\n");
	
	if (!(opt_flags & OPT_QUIET)) {
		printf("  When   Freq (MHz)   Elapsed  On Time   PWR L1   PWR L2   PWR L3   PWR L4   PWR L5\n");
	}

	signal(SIGINT, &handle_sigint);
	gettimeofday(&tv1, NULL);

	while (!stop_gpustat && (forever || count--)) {
		gputop_info info;
		unsigned long long clk;
		unsigned long long usec;

		if (nexus4_get_gputop(&info) < 0) {
			fprintf(stderr, "Failed to read GPU stats\n");
			ret = EXIT_FAILURE;
			break;
		}
		if (nexus4_get_gpuclk(&clk) < 0) {
			fprintf(stderr, "Failed to read GPU clock\n");
			ret = EXIT_FAILURE;
			break;
		}

		if (!(opt_flags & OPT_QUIET)) {
			printf("%6.1f    %8.3f   %8llu %8llu %8llu %8llu %8llu %8llu %8llu\n",
				whence,
				(double)clk / 1000000.0,
				info.elapsed_time,
				info.on_time,
				info.pwr_level[0],
				info.pwr_level[1],
				info.pwr_level[2],
				info.pwr_level[3],
				info.pwr_level[4]);
			fflush(stdout);
		}

		if (csv) {
			fprintf(csv, "%6.1f,%8.3f,%8llu,%8llu,%8llu,%8llu,%8llu,%8llu,%8llu\n",
				whence,
				(double)clk / 1000000.0,
				info.elapsed_time,
				info.on_time,
				info.pwr_level[0],
				info.pwr_level[1],
				info.pwr_level[2],
				info.pwr_level[3],
				info.pwr_level[4]);
			fflush(csv);
		}

		gettimeofday(&tv2, NULL);
		whence += duration;
		usec = ((whence + (double)(tv1.tv_sec - tv2.tv_sec)) * 1000000.0) +
			(double)(tv1.tv_usec - tv2.tv_usec);
		tv2.tv_sec = (time_t)usec / 1000000;
		tv2.tv_usec = (suseconds_t)usec % 1000000;
		select(0, NULL, NULL, NULL, &tv2);
	}

tidy:
	if (csv)
		fclose(csv);
	if (trace)
		gpu_trace_finish();

	exit(ret);
}
