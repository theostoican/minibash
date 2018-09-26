/**
 * Operating Systems 2013-2017 - Assignment 2
 *
 * STOICAN Theodor, 333CA
 * theodor.stoican@stud.acs.upb.ro
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	/* Execute cd */
	int ret;
	char *path = get_word(dir);

	if (path) {
		ret = chdir(path);
		free(path);
	} else {
		free(path);
		path = getenv("HOME");
		DIE(path == NULL, "Home envvar not set !");
		ret = chdir(path);
	}
	if (ret == 0)
		return true;
	else
		return false;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	return SHELL_EXIT;
}

/**
 * Clean the argument after allocating it (indirectly with get_argv).
 */
static void free_list_from_get_argv(char **wholeCommand)
{
	unsigned int i = 0;

	if (wholeCommand) {
		while (wholeCommand[i]) {
			free(wholeCommand[i]);
			wholeCommand[i] = NULL;
			i++;
		}
		free(wholeCommand);
		wholeCommand = NULL;
	}
}

/**
 * Perform redirection of stderr, stdout and stdin into a
 * file
 */
static void redirect(int fd, char *filename, int io_flags)
{
	int new_fd;
	int rc;

	if (fd == STDIN_FILENO) {
		new_fd = open(filename, O_RDONLY);
	} else {
		/**
		 * There are 2 possibilities :
		 *     -> appending to an existent file
		 *     -> creating/overwriting a file
		 */
		if (io_flags == IO_REGULAR) {
			new_fd = open(filename,
				O_WRONLY | O_CREAT | O_TRUNC, 0644);
		} else if (io_flags == IO_OUT_APPEND
					|| io_flags == IO_ERR_APPEND) {
			new_fd = open(filename,
				O_WRONLY | O_APPEND | O_CREAT, 0644);
		}
	}
	free(filename);
	DIE(new_fd < 0, "Error when opening file for redirection.");
	rc = dup2(new_fd, fd);
	DIE(rc < 0, "Error when duplicating fd for redirection.");
	rc = close(new_fd);
	DIE(rc < 0, "Error when closing.");
}

/**
 * After performing redirection, we must return to the old values of
 * standard input, output and error respectively.
 */
static void readjust_standard_values(int stdin_copy, int stdout_copy,
							int stderr_copy)
{
	int rc;

	rc = dup2(stdout_copy, STDOUT_FILENO);
	DIE(rc < 0, "Error when readjusting standard values");
	rc = dup2(stderr_copy, STDERR_FILENO);
	DIE(rc < 0, "Error when readjusting standard values");
	rc = dup2(stdin_copy, STDIN_FILENO);
	DIE(rc < 0, "Error when readjusting standard values");
	rc = close(stdout_copy);
	DIE(rc < 0, "Error when closing old standard values");
	rc = close(stderr_copy);
	DIE(rc < 0, "Error when closing old standard values");
	rc = close(stdin_copy);
	DIE(rc < 0, "Error when closing old standard values");
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	int size;
	int rc;
	int pid;
	int status;
	int ret = EXIT_SUCCESS;
	bool res;
	char *env_var_name, *env_var_value, *verb;
	char *env_assignment = NULL;
	int stdout_copy, stdin_copy, stderr_copy;
	char **wholeCommand;

	/**
	 * Sanity checks
	 */
	DIE(s == NULL, "Command is NULL.");

	/**
	 * It is guaranteed that verb is either the name
	 * of an internal command or an assignment of an
	 * environment variable.
	 */
	verb = get_word(s->verb);
	wholeCommand = get_argv(s, &size);
	stdout_copy = dup(STDOUT_FILENO);
	stderr_copy = dup(STDERR_FILENO);
	stdin_copy = dup(STDIN_FILENO);
	if (s->verb->next_part)
		env_assignment = (char *)s->verb->next_part->string;
	/**
	 * If builtin command, execute the command.
	 *
	 * Redirecting both stdout and stderr to one particular
	 * file doesn't work, probably because the file cursor
	 * is not shared; As a solution, I redirected stdout to
	 * the file and stderr to stdout; this way it flushes
	 * into the file just from stdout and not from stderr
	 * as well.
	 */
	if (s->out && s->err) {
		redirect(STDOUT_FILENO, get_word(s->out), s->io_flags);
		/**
		 * This is for cases like cat output1 &> final.
		 */
		if (strcmp(s->err->string, s->out->string) == 0) {
			dup2(STDOUT_FILENO, STDERR_FILENO);
		} else {
			/**
			 * This is for cases like cat output1 > final 2> err1.
			 */
			redirect(STDERR_FILENO, get_word(s->err), s->io_flags);
		}
	} else if (s->out) {
		redirect(STDOUT_FILENO, get_word(s->out), s->io_flags);
	} else if (s->err) {
		redirect(STDERR_FILENO, get_word(s->err), s->io_flags);
	}
	if (s->in)
		redirect(STDIN_FILENO, get_word(s->in), s->io_flags);

	/**
	 *Internal commands' part
	 */
	if (strcmp(verb, "exit") == 0 || strcmp(verb, "quit") == 0) {
		rc = shell_exit();
		readjust_standard_values(stdin_copy, stdout_copy, stderr_copy);
		free_list_from_get_argv(wholeCommand);
		free(verb);
		return rc;
	} else if (strcmp(verb, "cd") == 0) {
		res = shell_cd(s->params);
		readjust_standard_values(stdin_copy, stdout_copy, stderr_copy);
		free_list_from_get_argv(wholeCommand);
		free(verb);
		if (res)
			return EXIT_SUCCESS;
		else
			return EXIT_FAILURE;
	} else if (env_assignment && strcmp(env_assignment, "=") == 0) {
		env_var_name = (char *)s->verb->string;
		env_var_value = (char *)s->verb->next_part->next_part->string;
		setenv(env_var_name, env_var_value, 1);
		readjust_standard_values(stdin_copy, stdout_copy, stderr_copy);
		free_list_from_get_argv(wholeCommand);
		free(verb);
		return EXIT_SUCCESS;
	}

	/**
	 * If external command:
	 *   1. fork new process
	 *     2c. perform redirections in child
	 *     3c. load executable in child
	 *   2. wait for child
	 *   3. return exit status
	 */
	pid = fork();
	DIE(pid == -1, "Error when forking a process");
	switch (pid) {
	case 0:
		/*
		 * The child process will execute this
		 */
		rc = execvp(verb, wholeCommand);
		/*
		 * Could not start the new process
		 */
		fprintf(stderr, "Execution failed for '%s'\n", verb);
		exit(EXIT_FAILURE);
	default:
		readjust_standard_values(stdin_copy, stdout_copy, stderr_copy);
		free(verb);
		free_list_from_get_argv(wholeCommand);
		rc = waitpid(pid, &status, 0);
		DIE(rc == -1,
			"Error when waiting process with external command !");
		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status) != 0)
				ret = EXIT_FAILURE;
			else
				ret = WEXITSTATUS(status);
		}
		break;
	}
	return ret;
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool do_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	int pid;
	int rc, rc_child;
	int status;
	bool ret = false;
	/**
	 * Execute cmd1 and cmd2 simultaneously
	 */
	pid = fork();
	DIE(pid == -1, "Error when forking a process");
	switch (pid) {
	case 0:
		/**
		 * Execute cmd2 by child process
		 */
		rc = parse_command(cmd2, level, cmd2->up);
		exit(rc);

	default:
		/**
		 * Execute cmd1 by parent process
		 */
		rc = parse_command(cmd1, level, cmd1->up);
		rc_child = waitpid(pid, &status, 0);
		DIE(rc_child == -1,
			"Error when waiting process with external command !");
		rc_child = WEXITSTATUS(status);
		if (rc_child && rc)
			ret = true;
		else
			ret = false;
	}
	return ret;
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2)
 */
static bool do_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	int pid;
	int rc;
	int res;
	int status;
	int filedes[2];
	int stdin_copy = dup(STDIN_FILENO);
	bool ret = false;

	rc = pipe(filedes);
	DIE(rc < 0, "Error when opening anonymous pipe.");
	pid = fork();
	DIE(pid < 0, "Error when forking a process");
	switch (pid) {
	case 0:
		/*
		 * Child process reads from pipe
		 */
		rc = close(filedes[0]);
		DIE(rc < 0, "Error when closing.");
		rc = dup2(filedes[1], STDOUT_FILENO);
		DIE(rc < 0, "Error when opening file for redirection.");
		rc = close(filedes[1]);
		DIE(rc < 0, "Error when closing.");
		res = parse_command(cmd1, level + 1, father);
		rc = close(STDOUT_FILENO);
		DIE(rc < 0, "Error when closing stdout");
		exit(res);
	default:
		rc = close(filedes[1]);
		DIE(rc < 0, "Error when closing.");
		rc = dup2(filedes[0], STDIN_FILENO);
		DIE(rc < 0, "Error when opening file for redirection.");
		rc = close(filedes[0]);
		DIE(rc < 0, "Error when closing.");
		rc = parse_command(cmd2, level + 1, father);
		if (rc == 0)
			ret = true;
		rc = waitpid(pid, &status, 0);
		DIE(rc == -1,
			"Error when waiting process with external command !");
		rc = dup2(stdin_copy, STDIN_FILENO);
		DIE(rc < 0, "Error when remaking stdin.");
		rc = close(stdin_copy);
		DIE(rc < 0, "Error when closing stdin_copy");
	}
	return ret;
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	int rc;
	int ret = EXIT_SUCCESS;
	bool res = false;

	/**
	 * Sanity checks
	 */
	DIE(c == NULL, "Command is NULL.");

	if (c->op == OP_NONE) {
		/**
		 * Execute a simple command
		 */
		rc = parse_simple(c->scmd, level+1, c);
		return rc;
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		/**
		 * Execute the commands one after the other
		 */
		rc = parse_command(c->cmd1, level+1, c);
		/**
		 * Ignore return code of parse_command because in
		 * expr1; expr2, we need to execute expr2 regardless
		 * of the return code of expr1
		 */
		rc = parse_command(c->cmd2, level+1, c);
		break;

	case OP_PARALLEL:
		/**
		 * Execute the commands simultaneously
		 */
		res = do_in_parallel(c->cmd1, c->cmd2, level+1, c);
		if (res)
			ret = EXIT_SUCCESS;
		else
			ret = EXIT_FAILURE;
		break;

	case OP_CONDITIONAL_NZERO:
		/**
		 * Execute the second command only if the first one
		 * returns non zero
		 */
		rc = parse_command(c->cmd1, level+1, c);
		if (rc == EXIT_FAILURE) {
			rc = parse_command(c->cmd2, level+1, c);
			ret = rc;
		}
		break;

	case OP_CONDITIONAL_ZERO:
		/*
		 * Execute the second command only if the first one
		 * returns zero
		 */
		rc = parse_command(c->cmd1, level+1, c);
		if (rc == EXIT_SUCCESS) {
			rc = parse_command(c->cmd2, level+1, c);
			ret = rc;
		}
		break;

	case OP_PIPE:
		/*
		 * Redirect the output of the first command to the
		 * input of the second
		 */
		res = do_on_pipe(c->cmd1, c->cmd2, level+1, c);

		if (res)
			ret = EXIT_SUCCESS;
		else
			ret = EXIT_FAILURE;
		break;

	default:
		return SHELL_EXIT;
	}

	return ret;
}
