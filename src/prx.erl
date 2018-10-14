%%% @copyright 2015-2018 Michael Santos <michael.santos@gmail.com>

%%% Permission to use, copy, modify, and/or distribute this software for any
%%% purpose with or without fee is hereby granted, provided that the above
%%% copyright notice and this permission notice appear in all copies.
%%%
%%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
-module(prx).
-behaviour(gen_statem).
-include_lib("alcove/include/alcove.hrl").

-export([
        task/3, task/4,
        fork/0, fork/1,
        clone/2,
        execvp/2, execvp/3,
        execve/3, execve/4,
        fexecve/4,
        call/3,
        stdin/2,
        stop/1,
        start_link/1
    ]).

% Utilities
-export([
        controlling_process/2,
        stdio/2,
        replace_process_image/1, replace_process_image/3,
        sh/2, cmd/2
    ]).

% FSM state
-export([
        pidof/1,
        cpid/2,
        eof/2, eof/3,
        forkchain/1,
        drv/1,
        execed/1,
        atexit/2,
        sudo/0, sudo/1
    ]).

% Call wrappers
-export([
        setproctitle/2,
        setrlimit/3,
        getrlimit/2,
        select/5,
        cpid/1,
        parent/1,

        cap_enter/1,
        cap_fcntls_get/2,
        cap_fcntls_limit/3,
        cap_getmode/1,
        cap_ioctls_limit/3,
        cap_rights_limit/3,
        chdir/2,
        chmod/3,
        chown/4,
        chroot/2,
        clearenv/1,
        close/2,
        environ/1,
        exit/2,
        fcntl/3, fcntl/4,
        filter/2,
        getcpid/2, getcpid/3,
        getcwd/1,
        getenv/2,
        getgid/1,
        getgroups/1,
        gethostname/1,
        getopt/2,
        getpgrp/1,
        getpid/1,
        getpriority/3,
        getresgid/1,
        getresuid/1,
        getsid/2,
        getuid/1,
        ioctl/4,
        jail/2,
        kill/3,
        lseek/4,
        mkdir/3,
        mkfifo/3,
        mount/6, mount/7,
        open/3, open/4,
        pivot_root/3,
        pledge/3,
        prctl/6,
        ptrace/5,
        read/3,
        readdir/2,
        rmdir/2,
        seccomp/4,
        setcpid/3, setcpid/4,
        setenv/4,
        setgid/2,
        setgroups/2,
        sethostname/2,
        setns/2, setns/3,
        setopt/3,
        setpgid/3,
        setpriority/4,
        setresgid/4,
        setresuid/4,
        setsid/1,
        setuid/2,
        sigaction/3,
        socket/4,
        umount/2,
        unlink/2,
        unsetenv/2,
        unshare/2,
        waitpid/3,
        write/3
    ]).

% States
-export([
        call_state/3,
        exec_state/3
    ]).

% Behaviours
-export([init/1, callback_mode/0, terminate/3, code_change/4]).

-export_type([
              constant/0,
              cpid/0,
              cstruct/0,
              fd/0,
              gid_t/0,
              int32_t/0,
              int64_t/0,
              mode_t/0,
              off_t/0,
              pid_t/0,
              posix/0,
              prx_opt/0,
              ptr_arg/0,
              ptr_val/0,
              size_t/0,
              ssize_t/0,
              task/0,
              uid_t/0,
              uint32_t/0,
              uint64_t/0,
              waitstatus/0
             ]).

-type task() :: pid().

-type uint32_t() :: 0 .. 16#ffffffff.
-type uint64_t() :: 0 .. 16#ffffffffffffffff.

-type int32_t() :: -16#7fffffff .. 16#7fffffff.
-type int64_t() :: -16#7fffffffffffffff .. 16#7fffffffffffffff.

-type pid_t() :: int32_t().
-type fd() :: int32_t().

-type mode_t() :: uint32_t().
-type uid_t() :: uint32_t().
-type gid_t() :: uint32_t().
-type off_t() :: uint64_t().
-type size_t() :: uint64_t().
-type ssize_t() :: int64_t().

-type constant() :: atom() | integer().

-type posix() :: alcove:posix().

-type cstruct() :: nonempty_list(binary() | {ptr, binary() | non_neg_integer()}).
-type ptr_arg() :: binary() | constant() | cstruct().
-type ptr_val() :: binary() | integer() | cstruct().

-type prx_opt() :: maxchild
    | exit_status
    | maxforkdepth
    | termsig
    | flowcontrol
    | signaloneof.

-type waitstatus() :: {exit_status, int32_t()}
    | {termsig, atom()}
    | {stopsig, atom()}
    | continued.

-type cpid() :: #{pid := pid_t(),
                  flowcontrol := uint32_t(), signaloneof := uint32_t(),
                  exec := boolean(), fdctl := fd(),
                  stdin := fd(), stdout := fd(), stderr := fd()}.

-record(state, {
          owner :: pid(),
          stdio :: pid(),
          drv :: pid(),
          forkchain :: [pid_t()],
          parent = noproc :: task() | noproc,
          cpid = #{} :: #{} | #{pid() => pid_t()},
          atexit = fun(Drv, ForkChain, Pid) ->
                           prx_drv:call(Drv, ForkChain, close, [maps:get(stdout, Pid)]),
                           prx_drv:call(Drv, ForkChain, close, [maps:get(stdin, Pid)]),
                           prx_drv:call(Drv, ForkChain, close, [maps:get(stderr, Pid)])
                   end :: fun((pid(), [pid_t()], cpid()) -> any())
    }).

-define(SIGREAD_FILENO, 3).
-define(SIGWRITE_FILENO, 4).
-define(FDCTL_FILENO, 5).

-define(FD_SET, [?SIGREAD_FILENO, ?SIGWRITE_FILENO, ?FDCTL_FILENO]).

-define(PRX_CALL(Task_, Call_, Argv_),
    case gen_statem:call(Task_, {Call_, Argv_}, infinity) of
        {prx_error, Error_} ->
            erlang:error(Error_, [Task_|Argv_]);
        {error, undef} ->
            % reply from fork, clone when restricted by filter/1
            erlang:error(undef, [Task_|Argv_]);
        Error_ when Error_ =:= badarg; Error_ =:= undef ->
            erlang:error(Error_, [Task_|Argv_]);
        Reply_ ->
            Reply_
    end).

%%
%% Spawn a new task
%%

%% @doc fork(2) : create a new system process
%%
%% The behaviour of the process can be controlled by setting the
%% application environment:
%%
%% ```
%% Option = {exec, string()}
%%  | {progname, string()}
%%  | {ctldir, string()}
%% '''
%%
%% * `{exec, Exec}'
%%
%%  Default: ""
%%
%%  Sets a command to run the port under such as sudo or valgrind.
%%
%%  For example, to start the process as root using `sudo', allow running
%%  `prx' as root:
%%
%%  ```
%%  sudo visudo -f /etc/sudoers.d/99_prx
%%  <user> ALL = NOPASSWD: /path/to/prx/priv/prx
%%  Defaults!/path/to/alcove/priv/alcove !requiretty
%%  ```
%%
%%  Then:
%%
%%  ```
%%  application:set_env(prx, options, [{exec, "sudo -n"}])
%%  '''
%%
%% * `{progname, Path}'
%%
%%  Default: priv/prx
%%
%%  Sets the path to the prx executable.
%%
%% * `{ctldir, Path}'
%%
%%  Default: priv
%%
%%  A control directory writable by the prx port process (the Unix
%%  process may be running under a different user than the Erlang VM).
%%
%%  The control directory contains a FIFO shared by beam and the port
%%  process which is used to notify the Erlang VM that the port process
%%  has called exec().
-spec fork() -> {ok, task()} | {error, posix()}.
fork() ->
    start_link(self()).

%% @doc fork(2) : create a child process
%%
%% Forks child processes from an existing task. For example:
%%
%% ```
%% {ok, Task} = prx:fork(),             % PID 16341
%% {ok, Child1} = prx:fork(Task),       % PID 16349
%% {ok, Child2} = prx:fork(Task),       % PID 16352
%% {ok, Child2a} = prx:fork(Child2),    % PID 16354
%% {ok, Child2aa} = prx:fork(Child2a),  % PID 16357
%% {ok, Child2ab} = prx:fork(Child2a).  % PID 16482
%% '''
%%
%% Results in a process tree:
%%
%% ```
%% prx(16341)-+-prx(16349)
%%            `-prx(16352)---prx(16354)-+-prx(16357)
%%                                      `-prx(16482)
%% '''
-spec fork(task()) -> {ok, task()} | {error, posix()}.
fork(Task) when is_pid(Task) ->
    ?PRX_CALL(Task, fork, []).

%% @doc (Linux only) clone(2) : create a new process
-spec clone(task(), [constant()]) -> {ok, task()} | {error, posix()}.
clone(Task, Flags) when is_pid(Task) ->
    ?PRX_CALL(Task, clone, [Flags]).

-spec task(task(), [prx_task:op() | [prx_task:op()]], any())
    -> {ok, task()} | {error, posix()}.
task(Task, Ops, State) ->
    task(Task, Ops, State, []).

-spec task(task(), [prx_task:op() | [prx_task:op()]], any(), [prx_task:config()])
    -> {ok, task()} | {error, posix()}.
task(Task, Ops, State, Config) ->
    prx_task:do(Task, Ops, State, Config).

%% @doc terminate the task
-spec stop(task()) -> ok.
stop(Task) ->
    catch gen_statem:stop(Task),
    ok.

-spec start_link(pid()) -> {ok, task()} | {error, posix()}.
start_link(Owner) ->
    gen_statem:start_link(?MODULE, [Owner, init], []).

%%
%% call mode: request the task perform operations
%%

%% @doc Make a synchronous call into the port driver.
%%
%% The list of available calls and their arguments can be found here:
%%
%% [https://github.com/msantos/alcove#alcove-1]
%%
%% For example, to directly call `alcove:execve/5':
%%
%% ```
%% call(Task, execve,
%%  ["/bin/ls", ["/bin/ls", "-al"], ["HOME=/home/foo"]])
%% '''
-spec call(task(), atom(), [any()]) -> any().
call(_Task, fork, _Argv) ->
    {error,eagain};
call(_Task, clone, _Argv) ->
    {error,eagain};
call(Task, Call, Argv) ->
    ?PRX_CALL(Task, Call, Argv).

%%
%% exec mode: replace the process image, stdio is now a stream
%%

%% @doc execvp(2) : replace the current process image using the search path
-spec execvp(task(), [iodata()]) -> ok | {error, posix()}.
execvp(Task, [Arg0|_] = Argv) when is_list(Argv) ->
    ?PRX_CALL(Task, execvp, [Arg0, Argv]).

%% @doc execvp(2) : replace the current process image using the search path
%%
%% Allows setting the command name in the process list:
%% ```
%% prx:execvp(Task, "cat", ["name-in-process-list", "-n"])
%% '''
-spec execvp(task(), iodata(), [iodata()]) -> ok | {error, posix()}.
execvp(Task, Arg0, Argv) when is_list(Argv) ->
    ?PRX_CALL(Task, execvp, [Arg0, Argv]).

%% @doc execve(2) : replace the process image, specifying the environment
%% for the new process image.
-spec execve(task(), [iodata()], [iodata()]) -> ok | {error, posix()}.
execve(Task, [Arg0|_] = Argv, Env) when is_list(Argv), is_list(Env) ->
    ?PRX_CALL(Task, execve, [Arg0, Argv, Env]).

%% @doc execve(2) : replace the process image, specifying the environment
%% for the new process image.
%%
%% Allows setting the command name in the process list:
%% ```
%% prx:execve(Task, "/bin/cat", ["name-in-process-list", "-n"], ["VAR=1"])
%% '''
-spec execve(task(), iodata(), [iodata()], [iodata()]) -> ok | {error, posix()}.
execve(Task, Arg0, Argv, Env) when is_list(Argv), is_list(Env) ->
    ?PRX_CALL(Task, execve, [Arg0, Argv, Env]).

%% @doc fexecve(2) : replace the process image, specifying the environment
%% for the new process image, using a previously opened file descriptor. The
%% file descriptor can be set to close after exec() by passing the O_CLOEXEC
%% flag to open:
%% ```
%% {ok, FD} = prx:open(Task, "/bin/ls", [o_rdonly,o_cloexec]),
%% ok = prx:fexecve(Task, FD, ["-al"], ["FOO=123"]).
%% '''
%%
%% Linux and FreeBSD only. Linux requires an environment be set unlike
%% with execve(2). The environment can be empty:
%%
%% ```
%% % Environment required on Linux
%% ok = prx:fexecve(Task, FD, ["-al"], [""]),
%% [<<>>] = prx:environ(Task).
%% '''
-spec fexecve(task(), int32_t(), [iodata()], [iodata()]) -> ok | {error, posix()}.
fexecve(Task, FD, Argv, Env) when is_integer(FD), is_list(Argv), is_list(Env) ->
    ?PRX_CALL(Task, fexecve, [FD, [""|Argv], Env]).

% @doc Replace the port process image using execve(2)/fexecve(2)
%
% The call stack of the child processes grow because the port process
% forks recursively. The stack layout will also be the same as the parent,
% defeating ASLR protections.
%
% For most processes this is not a concern: the process will call exec()
% after performing some operations.
%
% Some "system" or "supervisor" type processes may remain in call mode:
% these processes can call replace_process_image/1 to exec() the port.
%
% On platforms supporting fexecve(2) (FreeBSD, Linux), prx will open a
% file descriptor to the port binary and use it to re-exec() the port.
%
% On other OS'es, execve(2) will be used with the the default path to
% the port binary.
%
% If the binary is not accessible or, on Linux, /proc is not mounted,
% replace_process_image/1 will fail.
-spec replace_process_image(task()) -> ok | {error, posix()}.
replace_process_image(Task) ->
    Drv = drv(Task),
    FD = gen_server:call(Drv, fdexe, infinity),
    Argv = alcove_drv:getopts([
            {progname, prx_drv:progname()},
            {depth, length(forkchain(Task))}
        ]),
    Env = environ(Task),
    case replace_process_image(Task, {fd, FD, Argv}, Env) of
        {error, Errno} when Errno =:= enosys; Errno =:= ebadf ->
            replace_process_image(Task, Argv, Env);
        Errno ->
            Errno
    end.

% @doc Replace the port process image using execve(2)/fexecve(2)
%
% Specify the port program path or a file descriptor to the binary and
% the process environment.
-spec replace_process_image(task(), {fd, int32_t(), iodata()}|iodata(), iodata())
    -> ok | {error, posix()}.
replace_process_image(_Task, {fd, -1, _Argv}, _Env) ->
    {error, ebadf};

replace_process_image(Task, {fd, FD, _} = Argv, Env) ->
    case setflag(Task, [FD], fd_cloexec, unset) of
        {error, _} = Error ->
            Error;
        ok ->
            Reply = replace_process_image_1(Task, Argv, Env),
            ok = setflag(Task, [FD], fd_cloexec, set),
            Reply
    end;

replace_process_image(Task, Argv, Env) ->
    replace_process_image_1(Task, Argv, Env).

replace_process_image_1(Task, Argv, Env) ->
    % Temporarily remove the close-on-exec flag: since these fd's are
    % part of the operation of the port, any errors are fatal and should
    % kill the OS process.
    ok = setflag(Task, ?FD_SET, fd_cloexec, unset),
    Reply = ?PRX_CALL(Task, replace_process_image, [Argv, Env]),
    ok = setflag(Task, ?FD_SET, fd_cloexec, set),
    Reply.

%% @doc Send data to the standard input of the process.
-spec stdin(task(), iodata()) -> ok.
stdin(Task, Buf) ->
    stdin_chunk(Task, iolist_to_binary(Buf)).

stdin_chunk(Task, <<Buf:32768/bytes, Rest/binary>>) ->
    gen_statem:cast(Task, {stdin, Buf}),
    stdin_chunk(Task, Rest);
stdin_chunk(Task, Buf) ->
    gen_statem:cast(Task, {stdin, Buf}).

%%
%% Utilities
%%
-spec cmd(task(), [iodata()]) -> binary() | {error, posix()}.
cmd(Task, Cmd) ->
    system(Task, Cmd).

-spec sh(task(), iodata()) -> binary() | {error, posix()}.
sh(Task, Cmd) ->
    cmd(Task, ["/bin/sh", "-c", Cmd]).


%%
%% Retrieve internal state
%%

-spec controlling_process(task(), pid()) -> ok | {error, badarg}.
controlling_process(Task, Pid) ->
    gen_statem:call(Task, {controlling_process, Pid}, infinity).

-spec stdio(task(), pid()) -> ok | {error, badarg}.
stdio(Task, Pid) ->
    gen_statem:call(Task, {stdio, Pid}, infinity).

-spec forkchain(task()) -> [pid_t()].
forkchain(Task) ->
    gen_statem:call(Task, forkchain, infinity).

-spec drv(task()) -> pid().
drv(Task) ->
    gen_statem:call(Task, drv, infinity).

-spec parent(task()) -> task() | noproc.
parent(Task) ->
    case is_process_alive(Task) of
        true ->
            gen_statem:call(Task, parent, infinity);

        false ->
            noproc
    end.

%% @doc retrieve process info for forked processes
%%
%% Retrieve the map for a child process as returned in prx:cpid/1.
%%
%% cpid/2 searches the list of a process' children for a PID (an erlang or
%% a system PID) and returns a map containing the parent's file descriptors
%% towards the child.
%%
-spec cpid(task(), task() | pid_t()) -> cpid() | error.
cpid(Task, Pid) when is_pid(Pid) ->
    case pidof(Pid) of
        noproc ->
            error;
        Proc ->
            cpid(Task, Proc)
    end;
cpid(Task, Pid) when is_integer(Pid) ->
    Children = prx:cpid(Task),
    find_cpid(Pid, Children).

%% @private
find_cpid(_Pid, []) ->
    error;
find_cpid(Pid, [#{pid := Pid} = Child|_Children]) ->
    Child;
find_cpid(Pid, [_Child|Children]) ->
    find_cpid(Pid, Children).

%% @doc close stdin of child process
-spec eof(task(), task() | pid_t()) -> ok | {error, posix()}.
eof(Task, Pid) ->
    eof(Task, Pid, stdin).

%% @doc close stdin, stdout or stderr of child process
-spec eof(task(), task() | pid_t(), stdin|stdout|stderr)
    -> ok | {error, posix()}.
eof(Task, Pid, Stdio) when Stdio == stdin; Stdio == stderr; Stdio == stdout ->
    case cpid(Task, Pid) of
        error ->
            {error, esrch};
        Child ->
            Fd = maps:get(Stdio, Child),
            close(Task, Fd)
    end.

%% @doc test if the task has called exec(2)
%%
%% Returns `true' if the task is running in exec mode.
-spec execed(task()) -> boolean().
execed(Task) ->
    case sys:get_state(Task) of
        {exec_state, _} -> true;
        _ -> false
    end.

%% @doc retrieves the system PID of the process similar to getpid(2)
%%
%% Returns the cached value for the PID of the system process.
%% ```
%% OSPid = prx:getpid(Task),
%% OSPid = prx:pidof(Task).
%% '''
-spec pidof(task()) -> pid_t() | noproc.
pidof(Task) ->
    case is_process_alive(Task) of
        true ->
            case forkchain(Task) of
                [] ->
                    Drv = drv(Task),
                    Port = gen_server:call(Drv, port, infinity),
                    proplists:get_value(os_pid, erlang:port_info(Port));
                Chain ->
                    lists:last(Chain)
            end;
        false ->
            noproc
    end.

%% @doc Register a function to be called at task termination
%%
%% The atexit function runs in the parent of the process. atexit/2 must
%% use prx_drv:call/4 to manipulate the task.
%%
%% The default function closes stdin, stdout and stderr of the system
%% process:
%%
%% ```
%% fun(Drv, ForkChain, Pid) ->
%%  prx_drv:call(Drv, ForkChain, close, [maps:get(stdout, Pid)]),
%%  prx_drv:call(Drv, ForkChain, close, [maps:get(stdin, Pid)]),
%%  prx_drv:call(Drv, ForkChain, close, [maps:get(stderr, Pid)])
%% end
%% '''
-spec atexit(task(), fun((pid(), [pid_t()], pid_t()) -> any())) -> ok.
atexit(Task, Fun) when is_function(Fun, 3) ->
    gen_statem:call(Task, {atexit, Fun}, infinity).

%% @doc Convenience function to fork a privileged process in the shell
%%
%% Sets the application environment so prx can fork a privileged
%% process. `sudo' must be configured to run the prx binary.
%%
%% The application environment must be set before prx:fork/0 is called.
%%
%% Equivalent to:
%% ```
%% application:set_env(prx, options, [{exec, "sudo -n"}]),
%% {ok, Task} = prx:fork(),
%% 0 = prx:getuid(Task).
%% '''
-spec sudo() -> ok.
sudo() ->
    sudo("sudo -n").

%% @doc Convenience function to fork a privileged process in the shell
%%
%% Allows specifying the command. For example, on OpenBSD:
%% ```
%% prx:sudo("doas"),
%% {ok, Task} = prx:fork(),
%% 0 = prx:getuid(Task).
%% '''
-spec sudo(string()) -> ok.
sudo(Exec) ->
    Env = application:get_env(prx, options, []),
    Opt = orddict:merge(fun(_Key, _V1, V2) -> V2 end,
            orddict:from_list(Env),
            orddict:from_list([{exec, Exec}])),
    application:set_env(prx, options, Opt).

%%%===================================================================
%%% gen_statem callbacks
%%%===================================================================

%% @private
callback_mode() ->
    state_functions.

%% @private
init([Owner, init]) ->
    process_flag(trap_exit, true),
    case prx_drv:start_link() of
        {ok, Drv} ->
            gen_server:call(Drv, init, infinity),
            {ok, call_state, #state{drv = Drv, forkchain = [], owner = Owner, stdio = Owner}};
        Error ->
            {stop, Error}
    end;
init([Drv, Owner, Parent, Chain, Call, Argv]) when Call == fork; Call == clone ->
    process_flag(trap_exit, true),
    case prx_drv:call(Drv, Chain, Call, Argv) of
        {ok, ForkChain} ->
            {ok, call_state, #state{drv = Drv, forkchain = ForkChain, owner = Owner, stdio = Owner, parent = Parent}};
        {prx_error, Error} ->
            erlang:error(Error, [Argv]);
        {error, Error} ->
            {stop, Error}
    end.

%% @private
handle_info({alcove_event, Drv, ForkChain, {exit_status, Status}}, _StateName, #state{
        drv = Drv,
        forkchain = ForkChain,
        stdio = Stdio
    } = State) ->
    Stdio ! {exit_status, self(), Status},
    {stop, shutdown, State};
handle_info({alcove_event, Drv, ForkChain, {termsig,Sig}}, _StateName, #state{
        drv = Drv,
        forkchain = ForkChain,
        stdio = Stdio
    } = State) ->
    Stdio ! {termsig, self(), Sig},
    {stop, shutdown, State};

handle_info({alcove_stdout, Drv, ForkChain, Buf}, exec_state, #state{
        drv = Drv,
        forkchain = ForkChain,
        stdio = Stdio
    } = State) ->
    Stdio ! {stdout, self(), Buf},
    {next_state, exec_state, State};
handle_info({alcove_stderr, Drv, ForkChain, Buf}, exec_state, #state{
        drv = Drv,
        forkchain = ForkChain,
        stdio = Stdio
    } = State) ->
    Stdio ! {stderr, self(), Buf},
    {next_state, exec_state, State};
handle_info({alcove_pipe, Drv, ForkChain, Bytes}, exec_state, #state{
        drv = Drv,
        forkchain = ForkChain,
        stdio = Stdio
    } = State) ->
    Stdio ! {stdin, self(), {error, {eagain, Bytes}}},
    {next_state, exec_state, State};

handle_info({alcove_stdout, Drv, ForkChain, Buf}, call_state, #state{
        drv = Drv,
        forkchain = ForkChain
    } = State) ->
    error_logger:error_report({stdout, Buf}),
    {next_state, call_state, State};
handle_info({alcove_stderr, Drv, ForkChain, Buf}, call_state, #state{
        drv = Drv,
        forkchain = ForkChain
    } = State) ->
    error_logger:error_report({stderr, Buf}),
    {next_state, call_state, State};
handle_info({alcove_pipe, Drv, ForkChain, Bytes}, call_state, #state{
        drv = Drv,
        forkchain = ForkChain,
        owner = Owner
    } = State) ->
    Owner ! {stdin, self(), {error, {eagain, Bytes}}},
    {stop, shutdown, State};

% The process control-on-exec fd has unexpectedly closed. The process
% has probably received a signal and been terminated.
handle_info({alcove_ctl, Drv, ForkChain, fdctl_closed}, call_state, #state{
        drv = Drv,
        forkchain = ForkChain
    } = State) ->
    {next_state, call_state, State};

handle_info({alcove_ctl, Drv, ForkChain, Buf}, call_state, #state{
        drv = Drv,
        forkchain = ForkChain
    } = State) ->
    error_logger:error_report({ctl, Buf}),
    {next_state, call_state, State};

handle_info({alcove_event, Drv, ForkChain, {signal, Signal, Info}}, call_state, #state{
        drv = Drv,
        forkchain = ForkChain,
        owner = Owner
    } = State) ->
    Owner ! {signal, self(), Signal, Info},
    {next_state, call_state, State};

handle_info({alcove_event, Drv, ForkChain, Buf}, call_state, #state{
        drv = Drv,
        forkchain = ForkChain
    } = State) ->
    error_logger:error_report({event, Buf}),
    {next_state, call_state, State};

handle_info({'EXIT', Drv, Reason}, _, #state{drv = Drv} = State) ->
    error_logger:error_report({'EXIT', Drv, Reason}),
    {stop, {shutdown, Reason}, State};

handle_info({'EXIT', Task, _Reason}, call_state, #state{
        drv = Drv,
        forkchain = ForkChain,
        cpid = Child,
        atexit = Atexit
    } = State) ->
    _ = case maps:find(Task, Child) of
        error ->
            ok;
        {ok, Pid} ->
            [ Atexit(Drv, ForkChain, cpid_to_map(X))
                    || X <- prx_drv:call(Drv, ForkChain, cpid, []), X#alcove_pid.pid =:= Pid ]
    end,
    {next_state, call_state, State};

handle_info(Info, Cur, State) ->
    error_logger:error_report({info, Cur, Info}),
    {next_state, Cur, State}.

%% @private
terminate(_Reason, _StateName, #state{drv = Drv, forkchain = []}) ->
    catch prx_drv:stop(Drv),
    ok;
terminate(_Reason, _StateName, #state{}) ->
    ok.

%% @private
code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

% Stdin sent while the process is in call state is discarded.
%% @private
call_state(cast, _, State) ->
    {next_state, call_state, State};

call_state({call, {Owner, _Tag} = From}, {Call, Argv}, #state{drv = Drv, forkchain = ForkChain, cpid = Child} = State) when Call =:= fork; Call =:= clone ->
    case gen_statem:start_link(?MODULE, [Drv, Owner, self(), ForkChain, Call, Argv], []) of
        {ok, Task} ->
            [Pid|_] = lists:reverse(prx:forkchain(Task)),
            {next_state, call_state,
             State#state{cpid = maps:put(Task, Pid, Child)},
             [{reply, From, {ok, Task}}]};
        Error ->
            {next_state, call_state, State, [{reply, From, Error}]}
    end;

call_state({call, {Owner, _Tag} = From}, {Call, Argv}, #state{
        drv = Drv,
        forkchain = ForkChain,
        owner = Owner
    } = State) when Call =:= execvp; Call =:= execve; Call =:= fexecve ->
    case prx_drv:call(Drv, ForkChain, cpid, []) of
        [] ->
            case prx_drv:call(Drv, ForkChain, Call, Argv) of
                ok ->
                    {next_state, exec_state, State, [{reply, From, ok}]};
                Error ->
                    {next_state, call_state, State, [{reply, From, Error}]}
            end;
        [#alcove_pid{}|_] ->
            {next_state, call_state, State, [{reply, From, {error,eacces}}]}
    end;

call_state({call, {Owner, _Tag} = From}, {replace_process_image, [{fd, FD, Argv}, Env]}, #state{
        drv = Drv,
        forkchain = ForkChain,
        owner = Owner
    } = State) ->
    case prx_drv:call(Drv, ForkChain, cpid, []) of
        [] ->
            Reply = prx_drv:call(Drv, ForkChain, fexecve, [FD, Argv, Env]),
            {next_state, call_state, State, [{reply, From, Reply}]};
        [#alcove_pid{}|_] ->
            {next_state, call_state, State, [{reply, From, {error,eacces}}]}
    end;
call_state({call, {Owner, _Tag} = From}, {replace_process_image, [[Arg0|_] = Argv, Env]}, #state{
        drv = Drv,
        forkchain = ForkChain,
        owner = Owner
    } = State) ->
    case prx_drv:call(Drv, ForkChain, cpid, []) of
        [] ->
            Reply = prx_drv:call(Drv, ForkChain, execve, [Arg0, Argv, Env]),
            {next_state, call_state, State, [{reply, From, Reply}]};
        [#alcove_pid{}|_] ->
            {next_state, call_state, State, [{reply, From, {error,eacces}}]}
    end;

call_state({call, {Owner, _Tag} = From}, {controlling_process, Pid}, #state{
        owner = Owner
    } = State) ->
    Reply = case is_process_alive(Pid) of
                false ->
                    {error, badarg};
                true ->
                    ok
            end,
    {next_state, call_state, State#state{owner = Pid, stdio = Pid}, [{reply, From, Reply}]};

call_state({call, {Owner, _Tag} = From}, {stdio, Pid}, #state{
        owner = Owner
    } = State) ->
    Reply = case is_process_alive(Pid) of
                false ->
                    {error, badarg};
                true ->
                    ok
            end,
    {next_state, call_state, State#state{stdio = Pid}, [{reply, From, Reply}]};

call_state({call, {Owner, _Tag} = From}, drv, #state{
        drv = Drv,
        owner = Owner
    } = State) ->
    {next_state, call_state, State, [{reply, From, Drv}]};

call_state({call, {Owner, _Tag} = From}, parent, #state{
        parent = Parent,
        owner = Owner
    } = State) ->
    {next_state, call_state, State, [{reply, From, Parent}]};

call_state({call, {_Owner, _Tag} = From}, forkchain, #state{
        forkchain = ForkChain
    } = State) ->
    {next_state, call_state, State, [{reply, From, ForkChain}]};

call_state({call, {Owner, _Tag} = From}, {atexit, Fun}, #state{
        owner = Owner
    } = State) ->
    {next_state, call_state, State#state{atexit = Fun}, [{reply, From, ok}]};

% port process calls exit
call_state({call, {Owner, _Tag} = From}, {exit, _}, #state{
        drv = Drv,
        owner = Owner,
        forkchain = []
    } = State) ->
    case prx_drv:call(Drv, [], cpid, []) of
        [] ->
            {stop_and_reply, shutdown, [{reply, From, ok}]};
        [#alcove_pid{}|_] ->
            {next_state, call_state, State, [{reply, From, {error,eacces}}]}
    end;

call_state({call, {Owner, _Tag} = From}, {Call, Argv}, #state{
        drv = Drv,
        forkchain = ForkChain,
        owner = Owner
    } = State) ->
    Reply = prx_drv:call(Drv, ForkChain, Call, Argv),
    {next_state, call_state, State, [{reply, From, Reply}]};

call_state({call, From}, _, State) ->
    {next_state, call_state, State, [{reply, From, {prx_error,eacces}}]};

call_state(info, Event, State) ->
    handle_info(Event, call_state, State).

%% @private
exec_state(cast, {stdin, Buf}, #state{drv = Drv, forkchain = ForkChain} = State) ->
    prx_drv:stdin(Drv, ForkChain, Buf),
    {next_state, exec_state, State};

exec_state(cast, _, State) ->
    {next_state, exec_state, State};

% Any calls received after the process has exec'ed crash the process:
%
% * the process could return an error tuple such as {error,einval} but this
%   would extend the type signature of all calls.
%
%   For example, getpid(2) cannot fail and returns a uint32_t():
%
%   getpid(Task) -> non_neg_integer() | {error,einval}
%
% * throw an exception: allow the caller to control failure by throwing
%   an exception. Since the caller expects a reply, the call cannot be
%   simply discarded.
%
%   Since the exception is sent between processes, erlang:exit/2 must
%   be used. Should the owner be killed (like with ports) or the caller?
%
% * stop the fsm
%
%   Fail fast: the process is in an unexpected state. There is no way
%   for the caller to control failure which makes experimenting in the shell
%   more difficult.
%
% * return a tuple and crash in the context of the caller
exec_state({call, From}, forkchain, #state{
        forkchain = ForkChain
    } = State) ->
    {next_state, exec_state, State, [{reply, From, ForkChain}]};

exec_state({call, From}, parent, #state{
        parent = Parent
    } = State) ->
    {next_state, exec_state, State, [{reply, From, Parent}]};

exec_state({call, {Owner, _Tag} = From}, {controlling_process, Pid}, #state{
        owner = Owner
    } = State) ->
    Reply = case is_process_alive(Pid) of
                false ->
                    {error, badarg};
                true ->
                    ok
            end,
    {next_state, exec_state, State#state{owner = Pid, stdio = Pid}, [{reply, From, Reply}]};

exec_state({call, {Owner, _Tag} = From}, {stdio, Pid}, #state{
        owner = Owner
    } = State) ->
    Reply = case is_process_alive(Pid) of
                false ->
                    {error, badarg};
                true ->
                    ok
            end,
    {next_state, exec_state, State#state{stdio = Pid}, [{reply, From, Reply}]};

exec_state({call, From}, _, State) ->
    {next_state, exec_state, State, [{reply, From, {prx_error,eacces}}]};

exec_state(info, Event, State) ->
    handle_info(Event, exec_state, State).

%%%===================================================================
%%% Internal functions
%%%===================================================================

system(Task, Cmd) ->
    process_flag(trap_exit, true),
    % Valid errors from sigaction are:
    %
    %   EINVAL: unknown signal, attempt to change SIGSTOP or SIGKILL
    %   EFAULT
    %
    % Since these signals are valid, an error means a fault has occurred
    % in the driver and the driver state is unknown, so crash hard.
    {ok, Int} = sigaction(Task, sigint, sig_ign),
    {ok, Quit} = sigaction(Task, sigquit, sig_ign),
    Reply = fork(Task),
    Stdout = case Reply of
        {ok, Child} ->
            % Restore the child's signal handlers before calling exec()
            {ok, _} = sigaction(Child, sigint, Int),
            {ok, _} = sigaction(Child, sigquit, Quit),

            % Disable flowcontrol if enabled
            true = prx:setcpid(Child, flowcontrol, -1),
            system_exec(Task, Child, Cmd);
        Error ->
            Error
    end,

    % Child has returned, restore the parent's signal handlers
    _ = case is_process_alive(Task) of
        true ->
            {ok, _} = sigaction(Task, sigint, Int),
            {ok, _} = sigaction(Task, sigquit, Quit);
        false ->
            ok
    end,
    Stdout.

system_exec(Task, Child, Cmd) ->
    case prx:execvp(Child, Cmd) of
        ok ->
            flush_stdio(Task, Child);
        Error ->
            stop(Child),
            Error
    end.

flush_stdio(Task, Child) ->
    flush_stdio(Task, Child, [], infinity).
flush_stdio(Task, Child, Acc, Timeout) ->
    receive
        {stdout, Child, Buf} ->
            flush_stdio(Task, Child, [Buf|Acc], Timeout);
        {stderr, Child, Buf} ->
            flush_stdio(Task, Child, [Buf|Acc], Timeout);
        {exit_status, Child, _} ->
            flush_stdio(Task, Child, Acc, 0);
        {termsig, Child, _} ->
            flush_stdio(Task, Child, Acc, 0);
        {exit_status, Task, _} ->
            flush_stdio(Task, Child, Acc, 0);
        {termsig, Task, _} ->
            flush_stdio(Task, Child, Acc, 0)
    after
        Timeout ->
            list_to_binary(lists:reverse(Acc))
    end.

setflag(_Task, [], _Flag, _Status) ->
    ok;
setflag(Task, [FD|FDSet], Flag, Status) ->
    Constant = ?PRX_CALL(Task, fcntl_constant, [Flag]),
    case fcntl(Task, FD, f_getfd) of
        {ok, Flags} ->
            case fcntl(Task, FD, f_setfd, fdstatus(Flags, Constant, Status)) of
                {ok, _NewFlags} ->
                    setflag(Task, FDSet, Flag, Status);
                Error1 ->
                    Error1
            end;
        Error ->
            Error
    end.

fdstatus(Flags, Constant, set) -> Flags bor Constant;
fdstatus(Flags, Constant, unset) -> Flags band (bnot Constant).

%%%===================================================================
%%% Exported functions
%%%===================================================================

%%%===================================================================
%%% Call wrappers
%%%
%%% Functions using the call interface:
%%%
%%% * provide type specs for calls
%%% * convert records to maps
%%% * provide portable versions of some calls
%%%
%%%===================================================================

%%
%% Portability
%%

%% @doc setproctitle(3) : set the process title
%%
%% Set the process title displayed in utilities like ps(1).
%%
%% Linux systems may also want to set the command name using prctl/6:
%%
%% ```
%% prx:prctl(Task, pr_set_name, <<"newname">>, 0, 0, 0)
%% '''
%%
-spec setproctitle(task(), iodata()) -> ok.
setproctitle(Task, Name) ->
    case os:type() of
        {unix,sunos} ->
            ok;
        {unix, OS} when OS =:= linux; OS =:= freebsd; OS =:= openbsd; OS =:= netbsd; OS =:= darwin ->
            ?PRX_CALL(Task, setproctitle, [Name]);
        _ ->
            ok
    end.

%%
%% Convert records to maps
%%

%% @doc Returns the list of child PIDs for this process.
%%
%% Each child task is a map composed of:
%%  * pid: system pid
%%  * exec: true if the child has called exec()
%%  * fdctl: parent end of CLOEXEC file descriptor used to monitor if
%%           the child process has called exec()
%%  * stdin: parent end of the child process' standard input
%%  * stdout: parent end of the child process' standard output
%%  * stderr: parent end of the child process' standard error
-spec cpid(task()) -> [cpid()].
cpid(Task) ->
    [ cpid_to_map(Pid) || Pid <- ?PRX_CALL(Task, cpid, []) ].

cpid_to_map(#alcove_pid{
        pid = Pid,
        flowcontrol = Flowcontrol,
        signaloneof = Signaloneof,
        fdctl = Ctl,
        stdin = In,
        stdout = Out,
        stderr = Err
    }) ->
    #{pid => Pid, exec => Ctl =:= -2,
      flowcontrol => Flowcontrol, signaloneof => Signaloneof,
      fdctl => Ctl, stdin => In, stdout => Out, stderr => Err}.

jail_to_map(#alcove_jail{
    version = Version,
    path = Path,
    hostname = Hostname,
    jailname = Jailname,
    ip4 = IP4,
    ip6 = IP6
    }) ->
    #{version => Version, path => Path, hostname => Hostname,
        jailname => Jailname, ip4 => IP4, ip6 => IP6}.

map_to_jail(Map0) ->
    #{version := Version,
      path := Path,
      hostname := Hostname,
      jailname := Jailname,
      ip4 := IP4,
      ip6 := IP6} = maps:merge(jail_to_map(#alcove_jail{}), Map0),
    #alcove_jail{
       version = Version,
       path = Path,
       hostname = Hostname,
       jailname = Jailname,
       ip4 = IP4,
       ip6 = IP6
      }.

%% @doc getrlimit(2) : retrieve the resource limits for a process
-spec getrlimit(task(), constant()) -> {ok, #{cur => uint64_t(), max => uint64_t()}} | {error, posix()}.
getrlimit(Task, Resource) ->
    case ?PRX_CALL(Task, getrlimit, [Resource]) of
        {ok, #alcove_rlimit{cur = Cur, max = Max}} ->
            {ok, #{cur => Cur, max => Max}};
        Error ->
            Error
    end.

%% @doc setrlimit(2) : set a resource limit
-spec setrlimit(task(), constant(), #{cur => uint64_t(), max => uint64_t()}) -> ok | {error, posix()}.
setrlimit(Task, Resource, Rlim) ->
    #{cur := Cur, max := Max} = Rlim,
    ?PRX_CALL(Task, setrlimit, [Resource, #alcove_rlimit{cur = Cur, max = Max}]).

%% @doc select(2) : poll a list of file descriptor for events
%%
%% select/5 will block until an event occurs on a file descriptor,
%% a timeout is reached or interrupted by a signal.
%%
%% The Timeout value may be:
%%
%% * `null' (block forever)
%%
%% * a map containing:
%% ```
%%   sec : number of seconds to wait
%%   usec : number of microseconds to wait
%% '''
%%
%% For example:
%% ```
%% {ok,[],[],[]} = prx:select(Task, [], [], [], #{sec => 10, usec => 100}).
%% '''
%%
-spec select(task(), [fd()], [fd()], [fd()], null | 'NULL' | #{sec => int64_t(), usec => int64_t()}) -> {ok, [fd()], [fd()], [fd()]} | {error,posix()}.
select(Task, Readfds, Writefds, Exceptfds, Timeout) when is_map(Timeout) ->
    Sec = maps:get(sec, Timeout, 0),
    Usec = maps:get(usec, Timeout, 0),
    ?PRX_CALL(Task, select, [Readfds, Writefds, Exceptfds, #alcove_timeval{sec = Sec, usec = Usec}]);
select(Task, Readfds, Writefds, Exceptfds, Timeout) ->
    ?PRX_CALL(Task, select, [Readfds, Writefds, Exceptfds, Timeout]).


%%
%% Convenience wrappers with types defined
%%

%% @doc (FreeBSD only) cap_enter(2) : put process into capability mode
-spec cap_enter(task()) -> 'ok' | {'error', posix()}.
cap_enter(Task) ->
    ?PRX_CALL(Task, cap_enter, []).

%% @doc (FreeBSD only) cap_fcntls_get(2) : get allowed fnctl(2)
%% commands on file descriptor
-spec cap_fcntls_get(task(), fd()) -> {'ok', int32_t()} | {'error', posix()}.
cap_fcntls_get(Task, Arg1) ->
    ?PRX_CALL(Task, cap_fcntls_get, [Arg1]).

%% @doc (FreeBSD only) cap_fcntls_limit(2) : set allowed fnctl(2)
%% commands on file descriptor
-spec cap_fcntls_limit(task(), fd(), [constant()])
    -> 'ok' | {'error', posix()}.
cap_fcntls_limit(Task, Arg1, Arg2) ->
    ?PRX_CALL(Task, cap_fcntls_limit, [Arg1, Arg2]).

%% @doc (FreeBSD only) cap_getmode(2) : returns capability mode status
%% of process
%%
%% * `0' : false
%% * `1' : true
%%
-spec cap_getmode(task()) -> {'ok', 0 | 1} | {'error', posix()}.
cap_getmode(Task) ->
    ?PRX_CALL(Task, cap_getmode, []).

%% @doc (FreeBSD only) cap_ioctls_limit(2) : set allowed ioctl(2)
%% commands on file descriptor
-spec cap_ioctls_limit(task(), fd(), [constant()])
    -> 'ok' | {'error', posix()}.
cap_ioctls_limit(Task, Arg1, Arg2) ->
    ?PRX_CALL(Task, cap_ioctls_limit, [Arg1, Arg2]).

%% @doc (FreeBSD only) cap_rights_limit(2) : set allowed rights(4)
%% of file descriptor
-spec cap_rights_limit(task(), fd(), [constant()])
    -> 'ok' | {'error', posix()}.
cap_rights_limit(Task, Arg1, Arg2) ->
    ?PRX_CALL(Task, cap_rights_limit, [Arg1, Arg2]).

%% @doc chdir(2) : change process current working directory.
-spec chdir(task(),iodata()) -> 'ok' | {'error', posix()}.
chdir(Task, Arg1) ->
    ?PRX_CALL(Task, chdir, [Arg1]).

%% @doc chmod(2) : change file permissions
-spec chmod(task(),iodata(),mode_t()) -> 'ok' | {'error', posix()}.
chmod(Task, Arg1, Arg2) ->
    ?PRX_CALL(Task, chmod, [Arg1, Arg2]).

%% @doc chown(2) : change file ownership
-spec chown(task(),iodata(),uid_t(),gid_t()) -> 'ok' | {'error', posix()}.
chown(Task, Arg1, Arg2, Arg3) ->
    ?PRX_CALL(Task, chown, [Arg1, Arg2, Arg3]).

%% @doc chroot(2) : change root directory
-spec chroot(task(),iodata()) -> 'ok' | {'error', posix()}.
chroot(Task, Arg1) ->
    ?PRX_CALL(Task, chroot, [Arg1]).

%% @doc clearenv(3) : zero process environment
-spec clearenv(task()) -> 'ok' | {'error', posix()}.
clearenv(Task) ->
    ?PRX_CALL(Task, clearenv, []).

%% @doc close(2) : close a file descriptor.
-spec close(task(),fd()) -> 'ok' | {'error', posix()}.
close(Task, Arg1) ->
    ?PRX_CALL(Task, close, [Arg1]).

%% @doc environ(7) : return the process environment variables
-spec environ(task()) -> [binary()].
environ(Task) ->
    ?PRX_CALL(Task, environ, []).

%% @doc exit(3) : cause the child process to exit
-spec exit(task(),int32_t()) -> 'ok'.
exit(Task, Arg1) ->
    ?PRX_CALL(Task, exit, [Arg1]).

%% @doc fcntl(2) : perform operation on a file descriptor
-spec fcntl(task(), fd(), constant()) -> {'ok',int64_t()} | {'error', posix()}.
fcntl(Task, Arg1, Arg2) ->
    ?PRX_CALL(Task, fcntl, [Arg1, Arg2, 0]).

%% @doc fcntl(2) : perform operation on a file descriptor with argument
-spec fcntl(task(), fd(), constant(), int64_t())
    -> {'ok',int64_t()} | {'error', posix()}.
fcntl(Task, Arg1, Arg2, Arg3) ->
    ?PRX_CALL(Task, fcntl, [Arg1, Arg2, Arg3]).

%% @doc filter() : restrict calls available to a control process
%%
%% filter/2 restricts calls for a prx control process. A control process
%% will continue to proxy data as well as monitor and reap subprocesses.
%%
%% Invoking a filtered call will crash the process with 'undef'.
%%
%% If the filter/1 call is filtered, subsequent calls to filter/1
%% will fail.
%%
%% Once a filter for a call is added, the call cannot be removed from
%% the filter set.
%%
%% Filters are inherited by the child process from the parent.
%%
%% ```
%% {ok, Ctrl} = prx:fork(),
%% {ok, Task} = prx:fork(Ctrl),
%%
%% ok = prx:filter(Ctrl, fork),
%% {'EXIT', {undef, _}} = (catch prx:fork(Ctrl)).
%% '''
-spec filter(task(), [constant()] | constant()) -> ok.
filter(Task, Calls0) when is_list(Calls0) ->
    case filter_map(Calls0) of
        {error, _} = Error ->
            Error;
        {ok, Calls} ->
            _ = [ filter(Task, Call) || Call <- Calls ],
            ok
    end;
filter(Task, Call) when is_atom(Call) ->
    case filter_constant(Call) of
      {error, _} = Error ->
          Error;
      {ok, N} ->
        filter(Task, N)
    end;
filter(Task, Call) when is_integer(Call) ->
    ?PRX_CALL(Task, filter, [Call]).

filter_constant(Call) when is_atom(Call) ->
    Result = try
               alcove_proto:call(Call)
             catch
               _:_ ->
                 {error, einval}
             end,
    case Result of
        {error, einval} ->
            Result;
        _ ->
            {ok, Result}
    end.

filter_map(Calls) ->
    filter_map(Calls, length(alcove_proto:calls()), []).

filter_map([], _Max, Acc) ->
    {ok, lists:reverse(Acc)};
filter_map([Call|Calls], Max, Acc) when is_integer(Call) andalso Call < Max ->
    filter_map(Calls, Max, [Call|Acc]);
filter_map([Call|Calls], Max, Acc) when is_atom(Call) ->
    case filter_constant(Call) of
        {error, einval} ->
            {error, einval};
        {ok, N} ->
            filter_map(Calls, Max, [N|Acc])
    end;
filter_map(_Calls, _Max, _Acc) ->
    {error, einval}.

%% @doc getcpid() : Get options for child process of prx control process
%%
%% Control behaviour of an exec()'ed process.
%%
%% See getcpid/3 for options.
-spec getcpid(task(), atom()) -> int32_t() | false.
getcpid(Task, Opt) ->
    case parent(Task) of
        noproc ->
            false;
        Parent ->
            getcpid(Parent, Task, Opt)
    end.

%% @doc getcpid() : Retrieve attributes set by the prx control process
%% for a child process
%%
%%    * flowcontrol: number of messages allowed from process
%%
%%        -1 : flowcontrol disabled
%%        0 : stdout/stderr for process is not read
%%        0+ : read this many messages from the process
%%
%%    * signaloneof: signal sent to child process on shutdown
-spec getcpid(task(), task() | cpid() | pid_t(), atom()) -> int32_t() | false.
getcpid(Task, Pid, Opt) when is_pid(Pid) ->
    case pidof(Pid) of
        noproc ->
            false;
        Proc ->
            getcpid(Task, Proc, Opt)
    end;
getcpid(Task, Pid, Opt) when is_integer(Pid) ->
		case cpid(Task, Pid) of
        error ->
            false;
        CPid ->
            getcpid(Task, CPid, Opt)
    end;
getcpid(_Task, CPid, Opt) when is_map(CPid) ->
    maps:get(Opt, CPid, false).

%% @doc getcwd(3) : return the current working directory
-spec getcwd(task()) -> {'ok', binary()} | {'error', posix()}.
getcwd(Task) ->
    ?PRX_CALL(Task, getcwd, []).

%% @doc getenv(3) : retrieve an environment variable
-spec getenv(task(),iodata()) -> binary() | 'false'.
getenv(Task, Arg1) ->
    ?PRX_CALL(Task, getenv, [Arg1]).

%% @doc getgid(2) : retrieve the processes' group ID
-spec getgid(task()) -> gid_t().
getgid(Task) ->
    ?PRX_CALL(Task, getgid, []).

%% @doc getgroups(2) : retrieve the list of supplementary groups
-spec getgroups(task()) -> {'ok', [gid_t()]} | {'error', posix()}.
getgroups(Task) ->
    ?PRX_CALL(Task, getgroups, []).

%% @doc gethostname(2) : retrieve the system hostname
-spec gethostname(task()) -> {'ok', binary()} | {'error', posix()}.
gethostname(Task) ->
    ?PRX_CALL(Task, gethostname, []).

%% @doc getopt() : get options for the prx control process
%%
%% Retrieve port options for a prx control process. These options are
%% configurable per process, with the default settings inherited
%% from the parent.
%%
%% The initial values for these options are set for the port by
%% prx:fork/0:
%%
%%     maxchild : non_neg_integer() : (ulimit -n) / 4 - 4
%%
%%         Number of child processes allowed for this process. This
%%         value can be modified by adjusting RLIMIT_NOFILE for
%%         the process.
%%
%%     exit_status : 1 | 0 : 1
%%
%%         Controls whether the controlling Erlang process is
%%         informed of a process' exit value.
%%
%%     maxforkdepth : non_neg_integer() : 16
%%
%%         Sets the maximum length of the fork chain.
%%
%%     termsig : 1 | 0 : 1
%%
%%         If a child process exits because of a signal, notify
%%         the controlling Erlang process.
%%
%%     flowcontrol : int32_t() : -1 (disabled)
%%
%%         Sets the default flow control behaviour for a newly
%%         forked process. Flow control is applied after the child
%%         process calls exec().
%%
%%         See setcpid/3,4.
%%
%%     signaloneof : 0-254 : 15
%%
%%         Send a signal to a child process on shutdown (stdin of
%%         the alcove control process is closed).
%%
%%         See setcpid/3,4.
-spec getopt(task(),prx_opt()) -> 'false' | int32_t().
getopt(Task, Arg1) ->
    ?PRX_CALL(Task, getopt, [Arg1]).

%% @doc getpgrp(2) : retrieve the process group.
-spec getpgrp(task()) -> pid_t().
getpgrp(Task) ->
    ?PRX_CALL(Task, getpgrp, []).

%% @doc getpid(2) : retrieve the system PID of the process.
-spec getpid(task()) -> pid_t().
getpid(Task) ->
    ?PRX_CALL(Task, getpid, []).

%% @doc getpriority(2) : retrieve scheduling priority of process,
%% process group or user
-spec getpriority(task(),constant(),int32_t()) -> {'ok',int32_t()} | {'error', posix()}.
getpriority(Task, Arg1, Arg2) ->
    ?PRX_CALL(Task, getpriority, [Arg1, Arg2]).

%% @doc getresgid(2) : get real, effective and saved group ID
%%
%% Supported on Linux and BSD's.
-spec getresgid(task()) -> {'ok', gid_t(), gid_t(), gid_t()} | {'error', posix()}.
getresgid(Task) ->
    ?PRX_CALL(Task, getresgid, []).

%% @doc getresuid(2) : get real, effective and saved user ID
%%
%% Supported on Linux and BSD's.
-spec getresuid(task()) -> {'ok', uid_t(), uid_t(), uid_t()} | {'error', posix()}.
getresuid(Task) ->
    ?PRX_CALL(Task, getresuid, []).

%% @doc getsid(2) : retrieve the session ID
-spec getsid(task(),pid_t()) -> {'ok', pid_t()} | {'error', posix()}.
getsid(Task, Arg1) ->
    ?PRX_CALL(Task, getsid, [Arg1]).

%% @doc getuid(2) : returns the process user ID
-spec getuid(task()) -> uid_t().
getuid(Task) ->
    ?PRX_CALL(Task, getuid, []).

%% @doc ioctl(2) : control device
%%
%% Controls a device using a file descriptor previously obtained
%% using open/4.
%%
%% Argp can be either a binary or a list representation of a C
%% struct. See prctl/6 below for a description of the list elements.
%%
%% On success, ioctl/4 returns a 2-tuple containing a map. The map keys are:
%%
%%      return_value: an integer equal to the return value of the ioctl.
%%
%%              Usually 0, however some ioctl's on Linux use the return
%%              value as the output parameter.
%%
%%      arg: the value depends on the type of the input parameter Argp.
%%
%%           cstruct: contains the contents of the memory pointed to by Argp
%%
%%           integer/binary: an empty binary
%%
%% An example of creating a tap device in a net namespace on Linux:
%%
%% ```
%% {ok, Child} = prx:clone(Task, [clone_newnet]),
%% {ok, FD} = prx:open(Child, "/dev/net/tun", [o_rdwr], 0),
%% {ok, #{return_value = 0, arg = <<"tap", N, _/binary>>}} = prx:ioctl(Child, FD,
%%     tunsetiff, <<
%%     0:(16*8), % generate a tuntap device name
%%     (16#0002 bor 16#1000):2/native-unsigned-integer-unit:8, % IFF_TAP, IFF_NO_PI
%%     0:(14*8)
%%     >>),
%% {ok, <<"tap", N>>}.
%% '''
-spec ioctl(task(), fd(), constant(), cstruct())
    -> {'ok', #{return_value := integer(), arg := iodata()}} | {'error', posix()}.
ioctl(Task, Arg1, Arg2, Arg3) ->
    case ?PRX_CALL(Task, ioctl, [Arg1, Arg2, Arg3]) of
        {ok, ReturnValue, Argp} ->
            {ok, #{return_value => ReturnValue, arg => Argp}};
        Error ->
            Error
    end.

%% @doc (FreeBSD only) jail(2) : restrict the current process in a system jail
-spec jail(task(),
    #{version => alcove:uint32_t(),
      path => iodata(),
      hostname => iodata(),
      jailname => iodata(),
      ip4 => [inet:ip4_address()],
      ip6 => [inet:ip6_address()]} | cstruct())
    -> {'ok', int32_t()} | {'error', posix()}.
jail(Task, Arg1) when is_map(Arg1) ->
    jail(Task, alcove_cstruct:jail(map_to_jail(Arg1)));
jail(Task, Arg1) ->
    ?PRX_CALL(Task, jail, [Arg1]).

%% @doc kill(2) : terminate a process
-spec kill(task(),pid_t(),constant()) -> 'ok' | {'error', posix()}.
kill(Task, Arg1, Arg2) ->
    ?PRX_CALL(Task, kill, [Arg1, Arg2]).

%% @doc lseek(2) : set file offset for read/write
-spec lseek(task(),fd(),off_t(),int32_t()) -> 'ok' | {'error', posix()}.
lseek(Task, Arg1, Arg2, Arg3) ->
    ?PRX_CALL(Task, lseek, [Arg1, Arg2, Arg3]).

%% @doc mkdir(2) : create a directory
-spec mkdir(task(),iodata(),mode_t()) -> 'ok' | {'error', posix()}.
mkdir(Task, Arg1, Arg2) ->
    ?PRX_CALL(Task, mkdir, [Arg1, Arg2]).

%% @doc mkfifo(3) : create a named pipe
-spec mkfifo(task(),iodata(),mode_t()) -> 'ok' | {'error', posix()}.
mkfifo(Task, Arg1, Arg2) ->
    ?PRX_CALL(Task, mkfifo, [Arg1, Arg2]).

%% @doc mount(2) : mount a filesystem, Linux style
%%
%% The arguments are:
%%
%% * `source'
%% * `target'
%% * `filesystem type'
%% * `flags'
%% * `data'
%%
%% An empty binary may be used to specify NULL.
%%
%% For example, filesystems mounted in a Linux mount namespace may be
%% visible in the global mount namespace. To avoid this, first remount the
%% root filesystem within mount namespace using the `MS_REC|MS_PRIVATE'
%% flags:
%%
%% ```
%% {ok, Task} = prx:clone(Parent, [clone_newns]),
%% ok = prx:mount(Task, "none", "/", <<>>, [ms_rec, ms_private], <<>>).
%% '''
%%
%% On BSD systems, the Source argument is ignored and passed to
%% the system mount call as:
%%
%%     mount(FSType, Target, Flags, Data);
%%
-spec mount(task(),iodata(),iodata(),iodata(),uint64_t() | [constant()],iodata()) -> 'ok' | {'error', posix()}.
mount(Task, Arg1, Arg2, Arg3, Arg4, Arg5) ->
    mount(Task, Arg1, Arg2, Arg3, Arg4, Arg5, <<>>).

%% @doc (Solaris only) mount(2) : mount a filesystem
%%
%% On Solaris, some mount options are passed in the Options argument
%% as a string of comma separated values terminated by a NULL.
%% Other platforms ignore the Options parameter.
-spec mount(task(),iodata(),iodata(),iodata(),uint64_t() | [constant()],iodata(),iodata()) -> 'ok' | {'error', posix()}.
mount(Task, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6) ->
    ?PRX_CALL(Task, mount, [Arg1, Arg2, Arg3, Arg4, Arg5, Arg6]).

%% @doc open(2) : returns a file descriptor associated with a file
%%
%% Lists of values are OR'ed:
%%
%% ```
%% prx:open(Task, "/etc/motd", [o_rdonly])
%% '''
-spec open(task(),iodata(),int32_t() | [constant()]) -> {'ok',fd()} | {'error', posix()}.
open(Task, Arg1, Arg2) ->
    open(Task, Arg1, Arg2, 0).

%% @doc open(2) : create a file, specifying permissions
%%
%% ```
%% prx:open(Task, "/tmp/test", [o_wronly,o_creat], 8#644)
%% '''
-spec open(task(),iodata(),int32_t() | [constant()],mode_t()) -> {'ok',fd()} | {'error', posix()}.
open(Task, Arg1, Arg2, Arg3) ->
    ?PRX_CALL(Task, open, [Arg1, Arg2, Arg3]).

%% @doc (Linux only) pivot_root(2) : change the root filesystem
-spec pivot_root(task(),iodata(),iodata()) -> 'ok' | {'error', posix()}.
pivot_root(Task, Arg1, Arg2) ->
    ?PRX_CALL(Task, pivot_root, [Arg1, Arg2]).

%% @doc (OpenBSD only) pledge(2) : restrict system operations
%% ```
%% prx:pledge(Task, "stdio proc exec", [])
%% '''
-spec pledge(task(),iodata(),[iodata()]) -> 'ok' | {'error', posix()}.
pledge(Task, Arg1, Arg2) ->
    ?PRX_CALL(Task, pledge, [Arg1, Arg2]).

%% @doc (Linux only) prctl(2) : operations on a process
%%
%% This function can be used to set BPF syscall filters on processes
%% (seccomp mode).
%%
%% A list can be used for prctl operations requiring a C structure
%% as an argument. List elements are used to contiguously populate
%% a buffer (it is up to the caller to add padding):
%%
%% * `binary()': the element is copied directly into the buffer
%%
%%    On return, the contents of the binary is returned to the
%%    caller.
%%
%% * `{ptr, N}': N bytes of zero'ed memory is allocated. The pointer
%%    is placed in the buffer.
%%
%%    On return, the contents of the memory is returned to the
%%    caller.
%%
%% * `{ptr, binary()}'
%%
%%    Memory equal to the size of the binary is allocated and
%%    initialized with the contents of the binary.
%%
%%    On return, the contents of the memory is returned to the
%%    caller.
%%
%% For example, to enforce a seccomp filter:
%%
%% ```
%% % NOTE: this filter will result in the port being sent a SIGSYS
%%
%% % The prx process requires the following syscalls to run:
%% %    sys_exit
%% %    sys_exit_group
%% %    sys_getrlimit
%% %    sys_poll
%% %    sys_read
%% %    sys_restart_syscall
%% %    sys_rt_sigreturn
%% %    sys_setrlimit
%% %    sys_sigreturn
%% %    sys_ugetrlimit
%% %    sys_write
%% %    sys_writev
%%
%% Arch = prx:call(Task, syscall_constant, [alcove:audit_arch]),
%% Filter = [
%%     ?VALIDATE_ARCHITECTURE(Arch),
%%     ?EXAMINE_SYSCALL,
%%     sys_read,
%%     sys_write
%% ],
%%
%% {ok,_,_,_,_,_} = prx:prctl(Task, pr_set_no_new_privs, 1, 0, 0, 0),
%% Pad = (erlang:system_info({wordsize,external}) - 2) * 8,
%%
%% Prog = [
%%     <<(iolist_size(Filter) div 8):2/native-unsigned-integer-unit:8>>,
%%     <<0:Pad>>,
%%     {ptr, list_to_binary(Filter)}
%% ],
%% prx:prctl(Task, pr_set_seccomp, seccomp_mode_filter, Prog, 0, 0).
%% '''
-spec prctl(task(),constant(),ptr_arg(),ptr_arg(),ptr_arg(),ptr_arg())
    -> {'ok',integer(),ptr_val(),ptr_val(),ptr_val(),ptr_val()} | {'error', posix()}.
prctl(Task, Arg1, Arg2, Arg3, Arg4, Arg5) ->
    ?PRX_CALL(Task, prctl, [Arg1, Arg2, Arg3, Arg4, Arg5]).

%% @doc (Linux only) ptrace(2) : trace processes
-spec ptrace(task(),constant(),pid_t(),ptr_arg(),ptr_arg())
    -> {'ok', integer(), ptr_val(), ptr_val()} | {'error', posix()}.
ptrace(Task, Arg1, Arg2, Arg3, Arg4) ->
    ?PRX_CALL(Task, ptrace, [Arg1, Arg2, Arg3, Arg4]).

%% @doc read(2) : read bytes from a file descriptor
-spec read(task(),fd(),size_t()) -> {'ok', binary()} | {'error', posix()}.
read(Task, Arg1, Arg2) ->
    ?PRX_CALL(Task, read, [Arg1, Arg2]).

%% @doc readdir(3) : retrieve list of objects in a directory
-spec readdir(task(),iodata()) -> {'ok', [binary()]} | {'error', posix()}.
readdir(Task, Arg1) ->
    ?PRX_CALL(Task, readdir, [Arg1]).

%% @doc rmdir(2) : delete a directory
-spec rmdir(task(),iodata()) -> 'ok' | {'error', posix()}.
rmdir(Task, Arg1) ->
    ?PRX_CALL(Task, rmdir, [Arg1]).

%% @doc seccomp(2) : restrict system operations
%%
%% See prctl/6.
-spec seccomp(task(), constant(), constant(), cstruct()) -> boolean().
seccomp(Task, Arg1, Arg2, Arg3) ->
    ?PRX_CALL(Task, seccomp, [Arg1, Arg2, Arg3]).

%% @doc setcpid() : Set options for child process of prx control process
%%
%% Control behaviour of an exec()'ed process.
%%
%% See setcpid/4 for options.
-spec setcpid(task(), atom(), int32_t()) -> boolean().
setcpid(Task, Opt, Val) ->
    case parent(Task) of
        noproc ->
            false;
        Parent ->
            setcpid(Parent, Task, Opt, Val)
    end.

%% @doc setcpid() : Set options for child process of prx control process
%%
%%    * flowcontrol: enable rate limiting of the stdout and stderr
%%      of a child process. stdin is not rate limited
%%      (default: -1 (disabled))
%%
%%        0 : stdout/stderr for process is not read
%%        1-2147483646 : read this many messages from the process
%%        -1 : disable flow control
%%
%%      NOTE: the limit applies to stdout and stderr. If the limit
%%      is set to 1, it is possible to get:
%%
%%        * 1 message from stdout
%%        * 1 message from stderr
%%        * 1 message from stdout and stderr
%%
%%    * signaloneof: the prx control process sends this signal
%%      to the child process on shutdown (default: 15 (SIGTERM))
-spec setcpid(task(), task() | cpid() | pid_t(), atom(), int32_t())
    -> boolean().
setcpid(Task, Pid, Opt, Val) when is_pid(Pid) ->
    case pidof(Pid) of
        noproc ->
            false;
        Proc ->
            setcpid(Task, Proc, Opt, Val)
    end;
setcpid(Task, CPid, Opt, Val) when is_map(CPid) ->
    #{pid := Pid} = CPid,
    setcpid(Task, Pid, Opt, Val);
setcpid(Task, CPid, Opt, Val) when is_integer(CPid) ->
    ?PRX_CALL(Task, setcpid, [CPid, Opt, Val]).

%% @doc setenv(3) : set an environment variable
-spec setenv(task(),iodata(),iodata(),int32_t()) -> 'ok' | {'error', posix()}.
setenv(Task, Arg1, Arg2, Arg3) ->
    ?PRX_CALL(Task, setenv, [Arg1, Arg2, Arg3]).

%% @doc setgid(2) : set the GID of the process
-spec setgid(task(),gid_t()) -> 'ok' | {'error', posix()}.
setgid(Task, Arg1) ->
    ?PRX_CALL(Task, setgid, [Arg1]).

%% @doc setgroups(2) : set the supplementary groups of the process
-spec setgroups(task(), [gid_t()]) -> 'ok' | {'error', posix()}.
setgroups(Task, Arg1) ->
    ?PRX_CALL(Task, setgroups, [Arg1]).

%% @doc sethostname(2) : set the system hostname
%%
%% This function is probably only useful if running in a uts namespace:
%%
%% ```
%% {ok, Child} = prx:clone(Task, [clone_newuts]),
%% ok = prx:sethostname(Child, "test"),
%% Hostname1 = prx:gethostname(Task),
%% Hostname2 = prx:gethostname(Child),
%% Hostname1 =/= Hostname2.
%% '''
-spec sethostname(task(),iodata()) -> 'ok' | {'error', posix()}.
sethostname(Task, Arg1) ->
    ?PRX_CALL(Task, sethostname, [Arg1]).

%% @doc (Linux only) setns(2) : attach to a namespace
%%
%% A process namespace is represented as a path in the /proc
%% filesystem. The path is `/proc/<pid>/ns/<ns>', where:
%%
%%  * `pid' = the system PID
%%
%%  * `ns' = a file representing the namespace
%%
%% The available namespaces is dependent on the kernel version. You
%% can see which are supported by running:
%%
%% ```
%%  ls -al /proc/$$/ns
%% '''
%%
%% For example, to attach to another process' network namespace:
%%
%% ```
%% {ok, Child1} = prx:clone(Task, [clone_newnet]),
%% {ok, Child2} = prx:fork(Task),
%%
%% % Move Child2 into the Child1 network namespace
%% {ok,FD} = prx:open(Child2,
%%  ["/proc/", integer_to_list(Child1), "/ns/net"], [o_rdonly], 0),
%% ok = prx:setns(Child2, FD, 0),
%% ok = prx:close(Child2, FD).
%% '''
-spec setns(task(),iodata()) -> 'ok' | {'error', posix()}.
setns(Task, Arg1) ->
    setns(Task, Arg1, 0).

%% @doc (Linux only) setns(2) : attach to a namespace, specifying
%% namespace type
%%
%% ```
%% ok = prx:setns(Task, FD, clone_newnet)
%% '''
-spec setns(task(),iodata(),constant()) -> 'ok' | {'error', posix()}.
setns(Task, Arg1, Arg2) ->
    ?PRX_CALL(Task, setns, [Arg1, Arg2]).

%% @doc setopt() : set options for the prx control process
%%
%% See getopt/3 for options.
-spec setopt(task(),prx_opt(), int32_t()) -> boolean().
setopt(Task, Arg1, Arg2) ->
    ?PRX_CALL(Task, setopt, [Arg1, Arg2]).

%% @doc setpgid(2) : set process group
-spec setpgid(task(),pid_t(),pid_t()) -> 'ok' | {'error', posix()}.
setpgid(Task, Arg1, Arg2) ->
    ?PRX_CALL(Task, setpgid, [Arg1, Arg2]).

%% @doc setpriority(2) : set scheduling priority of process, process
%% group or user
-spec setpriority(task(),constant(),int32_t(),int32_t()) -> 'ok' | {'error', posix()}.
setpriority(Task, Arg1, Arg2, Arg3) ->
    ?PRX_CALL(Task, setpriority, [Arg1, Arg2, Arg3]).

%% @doc setresgid(2) : set real, effective and saved group ID
%%
%% Supported on Linux and BSD's.
-spec setresgid(task(),gid_t(),gid_t(),gid_t()) -> 'ok' | {'error', posix()}.
setresgid(Task, Arg1, Arg2, Arg3) ->
    ?PRX_CALL(Task, setresgid, [Arg1, Arg2, Arg3]).

%% @doc setresuid(2) : set real, effective and saved user ID
%%
%% Supported on Linux and BSD's.
-spec setresuid(task(),uid_t(),uid_t(),uid_t()) -> 'ok' | {'error', posix()}.
setresuid(Task, Arg1, Arg2, Arg3) ->
    ?PRX_CALL(Task, setresuid, [Arg1, Arg2, Arg3]).

%% @doc setsid(2) : create a new session
-spec setsid(task()) -> {ok,pid_t()} | {error, posix()}.
setsid(Task) ->
    ?PRX_CALL(Task, setsid, []).

%% @doc setuid(2) : change UID
-spec setuid(task(),uid_t()) -> 'ok' | {'error', posix()}.
setuid(Task, Arg1) ->
    ?PRX_CALL(Task, setuid, [Arg1]).

%% @doc sigaction(2) : set process behaviour for signals
%%
%% * `sig_dfl' : uses the default behaviour for the signal
%%
%% * `sig_ign' : ignores the signal
%%
%% * `sig_info' : catches the signal and sends the controlling Erlang
%%                process an event: `{signal, atom(), Info}'
%%
%%               'Info' is a binary containing the siginfo_t
%%                structure. See sigaction(2) for details.
%%
%% * `<<>>' : retrieve current handler for signal
%%
%% Multiple caught signals of the same type may be reported as one event.
-spec sigaction(task(),constant(),atom() | <<>>)
    -> {'ok',atom()} | {'error', posix()}.
sigaction(Task, Arg1, Arg2) ->
    ?PRX_CALL(Task, sigaction, [Arg1, Arg2]).

%% @doc socket(2) : retrieve file descriptor for communication endpoint
%%
%% ```
%% {ok, FD} = prx:socket(Task, af_inet, sock_stream, 0).
%% '''
-spec socket(task(),constant(),constant(),int32_t())
    -> {'ok',fd()} | {'error', posix()}.
socket(Task, Arg1, Arg2, Arg3) ->
    ?PRX_CALL(Task, socket, [Arg1, Arg2, Arg3]).

%% @doc umount(2) : unmount a filesystem
%%
%% On BSD systems, calls unmount(2).
-spec umount(task(),iodata()) -> 'ok' | {error, posix()}.
umount(Task, Arg1) ->
    ?PRX_CALL(Task, umount, [Arg1]).

%% @doc unlink(2) : delete references to a file
-spec unlink(task(),iodata()) -> 'ok' | {error, posix()}.
unlink(Task, Arg1) ->
    ?PRX_CALL(Task, unlink, [Arg1]).

%% @doc unsetenv(3) : remove an environment variable
-spec unsetenv(task(),iodata()) -> 'ok' | {error, posix()}.
unsetenv(Task, Arg1) ->
    ?PRX_CALL(Task, unsetenv, [Arg1]).

%% @doc (Linux only) unshare(2) : allows creating a new namespace in
%% the current process
%%
%% unshare(2) lets you make a new namespace without calling clone(2):
%%
%% ```
%% % The port is now running in a namespace without network access.
%% ok = prx:unshare(Task, [clone_newnet]).
%% '''
-spec unshare(task(),int32_t() | [constant()]) -> 'ok' | {'error', posix()}.
unshare(Task, Arg1) ->
    ?PRX_CALL(Task, unshare, [Arg1]).

%% @doc waitpid(2) : wait for child process
%%
%% To use waitpid/3, disable handling of child processes by the event
%% loop:
%%
%% ```
%% {ok, sig_dfl} = prx:sigaction(Task, sigchld, sig_info),
%% {ok, Child} = prx:fork(Task),
%% Pid = prx:getpid(Child),
%% ok = prx:exit(Child, 2),
%% {ok, Pid, _, [{exit_status, 2}]} = prx:waitpid(Task, Pid, [wnohang]).
%% '''
-spec waitpid(task(), pid_t(), int32_t() | [constant()])
    -> {'ok', pid_t(), int32_t(), [waitstatus()]} | {'error', posix()}.
waitpid(Task, Arg1, Arg2) ->
    ?PRX_CALL(Task, waitpid, [Arg1, Arg2]).

%% @doc write(2): writes a buffer to a file descriptor and returns the
%%      number of bytes written.
-spec write(task(),fd(),iodata()) -> {'ok', ssize_t()} | {'error', posix()}.
write(Task, Arg1, Arg2) ->
    ?PRX_CALL(Task, write, [Arg1, Arg2]).
