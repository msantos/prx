%%% @copyright 2015-2022 Michael Santos <michael.santos@gmail.com>

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
    reexec/1, reexec/3,
    replace_process_image/1, replace_process_image/3,
    sh/2,
    cmd/2
]).

% FSM state
-export([
    pidof/1,
    cpid/2,
    eof/2, eof/3,
    pipeline/1,
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
    filter/2, filter/3,
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
    procctl/5,
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
    umount2/3,
    unlink/2,
    unsetenv/2,
    unshare/2,
    unveil/3,
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
    call/0,
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

-type call() ::
    alcove_proto:call()
    | reexec
    | replace_process_image
    | getcpid.

-type task() :: pid().

-type uint32_t() :: 0..16#ffffffff.
-type uint64_t() :: 0..16#ffffffffffffffff.

-type int32_t() :: -16#7fffffff..16#7fffffff.
-type int64_t() :: -16#7fffffffffffffff..16#7fffffffffffffff.

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

-type prx_opt() ::
    maxchild
    | exit_status
    | maxforkdepth
    | termsig
    | flowcontrol
    | signaloneof.

-type waitstatus() ::
    {exit_status, int32_t()}
    | {termsig, atom()}
    | {stopsig, atom()}
    | continued.

-type cpid() :: #{
    pid := pid_t(),
    flowcontrol := uint32_t(),
    signaloneof := uint32_t(),
    exec := boolean(),
    fdctl := fd(),
    stdin := fd(),
    stdout := fd(),
    stderr := fd()
}.

-record(state, {
    owner :: pid(),
    stdio :: pid(),
    drv :: pid(),
    pipeline :: [pid_t()],
    parent = noproc :: task() | noproc,
    children = #{} :: #{} | #{pid() => pid_t()},
    sigaction = #{} :: #{} | #{atom() => fun((pid(), [pid_t()], atom(), binary()) -> any())},
    atexit = fun(Drv, Pipeline, Pid) ->
        prx_drv:call(Drv, Pipeline, close, [maps:get(stdout, Pid)]),
        prx_drv:call(Drv, Pipeline, close, [maps:get(stdin, Pid)]),
        prx_drv:call(Drv, Pipeline, close, [maps:get(stderr, Pid)])
    end :: fun((pid(), [pid_t()], cpid()) -> any())
}).

-define(SIGREAD_FILENO, 3).
-define(SIGWRITE_FILENO, 4).
-define(FDCTL_FILENO, 5).

-define(FD_SET, [?SIGREAD_FILENO, ?SIGWRITE_FILENO, ?FDCTL_FILENO]).

-define(PRX_CALL(Task_, Call_, Argv_),
    case gen_statem:call(Task_, {Call_, Argv_}, infinity) of
        {prx_error, Error_} ->
            erlang:error(Error_, [Task_ | Argv_]);
        {error, undef} ->
            % reply from fork, clone when restricted by filter/1
            erlang:error(undef, [Task_ | Argv_]);
        Error_ when Error_ =:= badarg; Error_ =:= undef ->
            erlang:error(Error_, [Task_ | Argv_]);
        Reply_ ->
            Reply_
    end
).

%%
%% Spawn a new task
%%

%% @doc fork(2): create a new system process
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
%% • `{exec, Exec}'
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
%%  Defaults!/path/to/prx/priv/prx !requiretty
%%  ```
%%
%%  Then:
%%
%%  ```
%%  application:set_env(prx, options, [{exec, "sudo -n"}])
%%  '''
%%
%% • `{progname, Path}'
%%
%%  Default: priv/prx
%%
%%  Sets the path to the prx executable.
%%
%% • `{ctldir, Path}'
%%
%%  Default: priv
%%
%%  A control directory writable by the prx port process (the Unix
%%  process may be running under a different user than the Erlang VM).
%%
%%  The control directory contains a FIFO shared by beam and the port
%%  process which is used to notify the Erlang VM that the port process
%%  has called exec().
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.187.0>}
%% '''
-spec fork() -> {ok, task()} | {error, posix()}.
fork() ->
    start_link(self()).

%% @doc fork(2): create a child process
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
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.187.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.191.0>}
%% 3> prx:cpid(Task).
%% [#{exec => false,fdctl => 8,flowcontrol => -1,pid => 8098,
%%    signaloneof => 15,stderr => 13,stdin => 10,stdout => 11}]
%% '''
-spec fork(task()) -> {ok, task()} | {error, posix()}.
fork(Task) when is_pid(Task) ->
    ?PRX_CALL(Task, fork, []).

%% @doc clone(2): create a new process
%%
%% == Support ==
%%
%% • Linux
%%
%% == Examples ==
%%
%% ```
%% 1> prx:sudo().
%% ok
%% 2> {ok, Task} = prx:fork().
%% {ok,<0.180.0>}
%% 3> {ok, Task1} = prx:clone(Task, [clone_newns, clone_newpid, clone_newipc, clone_newuts, clone_newnet]).
%% {ok,<0.184.0>}
%% 4> prx:getpid(Task1).
%% 1
%% '''
-spec clone(task(), Flags :: [constant()]) -> {ok, task()} | {error, posix()}.
clone(Task, Flags) when is_pid(Task) ->
    ?PRX_CALL(Task, clone, [Flags]).

%% @doc Fork a subprocess and run a sequence of operations
%%
%% task/3 uses `fork/1' to create a new subprocess and run a sequence
%% of system calls. If an operations fails, the subprocess is sent SIGKILL
%% and exits.
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.349.0>}
%% 2> {ok, Task1} = prx:task(Task, [
%% 2>     {chdir, ["/"]},
%% 2>     {setrlimit, [rlimit_core, #{cur => 0, max => 0}]},
%% 2>     {prx, chdir, ["/nonexistent"], [{errexit, false}]}
%% 2> ], []).
%% {ok,<0.382.0>}
%% 3> prx:getrlimit(Task1, rlimit_core).
%% {ok,#{cur => 0,max => 0}}
%% 4> prx:getcwd(Task1).
%% {ok,<<"/">>}
%% '''
%%
%% @see task/4
-spec task(task(), Ops :: [prx_task:op() | [prx_task:op()]], State :: any()) ->
    {ok, task()} | {error, posix()}.
task(Task, Ops, State) ->
    task(Task, Ops, State, []).

%% @doc Create a subprocess and run a sequence of operations using optional
%% function calls
%%
%% task/4 calls the optional `init' function provided in the `Config'
%% argument to create a new subprocess. The default `init' function uses
%% `fork/1'.
%%
%% The subprocess next performs a list of operations. Operations are
%% tuples consisting of:
%%
%% * the module name: optional if modifier is not present, defaults to `prx'
%%
%% * the module function
%%
%% * function arguments
%%
%% * modifier list
%%
%% ```
%% [
%%  % equivalent to prx:setresgid(65534, 65534, 65534)
%%  {setresgid, [65534, 65534, 65534]},
%%
%%  % equivalent to prx:setresuid(65534, 65534, 65534), error is ignored
%%  {prx, setresuid, [65534, 65534, 65534], [{errexit, false}]},
%% ]
%% '''
%%
%% If an operation returns `{error, term()}', the sequence of operations
%% is aborted and the `terminate' function is run. The default `terminate'
%% functions signals the subprocess with SIGKILL.
%%
%% == Examples ==
%%
%% ```
%% 1> Init = fun(Parent) ->
%% 1>     prx:clone(Parent, [
%% 1>         clone_newnet,
%% 1>         clone_newuser
%% 1>     ])
%% 1> end.
%% #Fun<erl_eval.44.65746770>
%% 2> Terminate = fun(Parent, Child) ->
%% 2>     prx:stop(Child),
%% 2>     prx:kill(Parent, prx:pidof(Child), sigterm)
%% 2> end.
%% #Fun<erl_eval.43.65746770>
%% 3> {ok, Task} = prx:fork().
%% 4> {ok, Task1} = prx:task(Task, [
%% 4>     {chdir, ["/"]},
%% 4>     {setrlimit, [rlimit_core, #{cur => 0, max => 0}]},
%% 4>     {prx, chdir, ["/nonexistent"], [{errexit, false}]}
%% 4> ], [], [
%% 4>     {init, Init},
%% 4>     {terminate, Terminate}
%% 4> ]).
%% {ok,<0.398.0>}
%% 5> prx:execvp(Task1, ["ip", "a"]).
%% ok
%% 27> flush().
%% Shell got {stdout,<0.398.0>,
%%                   <<"1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1000\n    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n">>}
%% Shell got {exit_status,<0.398.0>,0}
%% ok
%% '''
%%
%% @see prx_task
-spec task(
    task(), Ops :: [prx_task:op() | [prx_task:op()]], State :: any(), Config :: [prx_task:config()]
) ->
    {ok, task()} | {error, posix()}.
task(Task, Ops, State, Config) ->
    prx_task:do(Task, Ops, State, Config).

%% @doc Terminate the task
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.180.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.184.0>}
%% 4> prx:stop(Task1).
%% ok
%% 5> prx:cpid(Task).
%% []
%% '''
-spec stop(task()) -> ok.
stop(Task) ->
    catch gen_statem:stop(Task),
    ok.

%% @private
-spec start_link(pid()) -> {ok, task()} | {error, posix()}.
start_link(Owner) ->
    gen_statem:start_link(?MODULE, [Owner, init], []).

%%
%% call mode: request the task perform operations
%%

%% @doc Make a synchronous call into the port driver
%%
%% The list of available calls and their arguments can be found here:
%%
%% [https://hexdocs.pm/alcove/alcove.html#functions]
%%
%% For example, to directly call `alcove:execve/5':
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.180.0>}
%% 2> prx:call(Task, execve, ["/bin/ls", ["/bin/ls", "-al"], ["HOME=/home/foo"]]).
%% ok
%% '''
-spec call(task(), call(), [any()]) -> any().
call(_Task, fork, _Argv) ->
    {error, eagain};
call(_Task, clone, _Argv) ->
    {error, eagain};
call(Task, Call, Argv) ->
    ?PRX_CALL(Task, Call, Argv).

%%
%% exec mode: replace the process image, stdio is now a stream
%%

%% @doc execvp(2): replace the current process image using the search path
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.180.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.194.0>}
%% 3> prx:execvp(Task1, ["cat", "-n"]).
%% ok
%% 4> prx:stdin(Task1, <<"test\n">>).
%% ok
%% 5> flush().
%% Shell got {stdout,<0.194.0>,<<"     1\ttest\n">>}
%% ok
%% '''
-spec execvp(task(), [iodata()]) -> ok | {error, posix()}.
execvp(Task, [Arg0 | _] = Argv) when is_list(Argv) ->
    ?PRX_CALL(Task, execvp, [Arg0, Argv]).

%% @doc execvp(2): replace the current process image using the search path
%%
%% == Examples ==
%%
%% Set the command name in the process list:
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.180.0>}
%% 2> prx:execvp(Task, "cat", ["name-in-process-list", "-n"])
%% ok
%% '''
-spec execvp(task(), iodata(), [iodata()]) -> ok | {error, posix()}.
execvp(Task, Arg0, Argv) when is_list(Argv) ->
    ?PRX_CALL(Task, execvp, [Arg0, Argv]).

%% @doc execve(2): replace process image with environment
%%
%% Replace the process image, specifying the environment for the new
%% process image.
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.180.0>}
%% 2> prx:execvp(Task, "cat", ["name-in-process-list", "-n"])
%% ok
%% '''
-spec execve(task(), [iodata()], [iodata()]) -> ok | {error, posix()}.
execve(Task, [Arg0 | _] = Argv, Env) when is_list(Argv), is_list(Env) ->
    ?PRX_CALL(Task, execve, [Arg0, Argv, Env]).

%% @doc execve(2): replace process image with environment
%%
%% Replace the process image, specifying the environment for the new
%% process image.
%%
%% == Examples ==
%%
%% Set the command name in the process list:
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.180.0>}
%% 2> prx:execve(Task, "/bin/cat", ["name-in-process-list", "-n"], ["VAR=1"]).
%% ok
%% '''
-spec execve(task(), iodata(), [iodata()], [iodata()]) -> ok | {error, posix()}.
execve(Task, Arg0, Argv, Env) when is_list(Argv), is_list(Env) ->
    ?PRX_CALL(Task, execve, [Arg0, Argv, Env]).

%% @doc fexecve(2): replace the process image
%%
%% Replace the process image, specifying the environment for the new process
%% image, using a previously opened file descriptor.  The file descriptor
%% can be set to close after exec() by passing the O_CLOEXEC flag to open:
%%
%% ```
%% {ok, FD} = prx:open(Task, "/bin/ls", [o_rdonly,o_cloexec]),
%% ok = prx:fexecve(Task, FD, ["-al"], ["FOO=123"]).
%% '''
%%
%% Linux requires an environment to be set unlike with execve(2). The
%% environment can be empty:
%%
%% ```
%% % Environment required on Linux
%% ok = prx:fexecve(Task, FD, ["ls", "-al"], [""]).
%% '''
%%
%% == Support ==
%%
%% • Linux
%%
%% • FreeBSD
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.180.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.184.0>}
%% 3> {ok, FD} = prx:open(Task1, "/usr/bin/env", [o_rdonly,o_cloexec], 0).
%% {ok,7}
%% 4> prx:fexecve(Task1, FD, ["env", "-0"], ["FOO=123"]).
%% ok
%% 5> flush().
%% Shell got {stdout,<0.208.0>,<<70,79,79,61,49,50,51,0>>}
%% Shell got {exit_status,<0.208.0>,0}
%% ok
%% '''
-spec fexecve(task(), int32_t(), [iodata()], [iodata()]) -> ok | {error, posix()}.
fexecve(Task, FD, Argv, Env) when is_integer(FD), is_list(Argv), is_list(Env) ->
    ?PRX_CALL(Task, fexecve, [FD, ["" | Argv], Env]).

%% @equiv reexec/1
-spec replace_process_image(task()) -> ok | {error, posix()}.
replace_process_image(Task) ->
    reexec(Task).

%% @equiv reexec/3
-spec replace_process_image(
    task(), {fd, int32_t(), [string() | [string()]]} | [string() | [string()]], iodata()
) ->
    ok | {error, posix()}.
replace_process_image(Task, Argv, Env) ->
    reexec(Task, Argv, Env).

%% @doc Fork+exec prx process.
%%
%% Fork+exec is a way of randomizing the memory space of a process:
%%
%% [https://poolp.org/posts/2016-09-12/opensmtpd-6.0.0-is-released/]
%%
%% prx processes fork recursively:
%%
%% • the calls stack increases in size
%%
%% • the memory space layout is identical to the parent
%%
%% After forking a prx process using fork/1, the controlling process will
%% typically instruct the new prx process to execute a command using one
%% of the exec(3) functions: execvp/2, execve/3.
%%
%% Some "system" or "supervisor" type processes may remain in call mode:
%% these processes can call reexec/1 to exec() the port.
%%
%% On platforms supporting fexecve(2) (FreeBSD, Linux), prx will open a
%% file descriptor to the port binary and use it to re-exec() the port.
%%
%% On other OS'es, execve(2) will be used with the the default path to
%% the port binary.
%%
%% If the binary is not accessible or, on Linux, /proc is not mounted,
%% reexec/1 will fail.
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.180.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.216.0>}
%% 2> prx:getpid(Task1).
%% 8175
%% 3> prx:reexec(Task1).
%% ok
%% 4> prx:getpid(Task1).
%% 8175
%% '''
-spec reexec(task()) -> ok | {error, posix()}.
reexec(Task) ->
    Drv = drv(Task),
    FD = gen_server:call(Drv, fdexe, infinity),
    Argv = alcove_drv:getopts([
        {progname, prx_drv:progname()},
        {depth, length(pipeline(Task))},
        {maxchild, getopt(Task, maxchild)}
    ]),
    Env = environ(Task),
    Opts = getopts(Task),
    Result =
        case reexec(Task, {fd, FD, Argv}, Env) of
            {error, Errno} when Errno =:= enosys; Errno =:= ebadf ->
                reexec(Task, Argv, Env);
            Errno ->
                Errno
        end,

    case Result of
        ok ->
            _ = setopts(Task, Opts),
            Result;
        _ ->
            Result
    end.

%% @doc Replace the port process image using execve(2)/fexecve(2).
%%
%% Specify the port program path or a file descriptor to the binary and
%% the process environment.
%%
%% @see reexec/1
-spec reexec(task(), {fd, int32_t(), [string() | [string()]]} | [string() | [string()]], iodata()) ->
    ok | {error, posix()}.
reexec(_Task, {fd, -1, _Argv}, _Env) ->
    {error, ebadf};
reexec(Task, {fd, FD, _} = Argv, Env) ->
    case setflag(Task, [FD], fd_cloexec, unset) of
        {error, _} = Error ->
            Error;
        ok ->
            Reply = reexec_1(Task, Argv, Env),
            ok = setflag(Task, [FD], fd_cloexec, set),
            Reply
    end;
reexec(Task, Argv, Env) ->
    reexec_1(Task, Argv, Env).

reexec_1(Task, Argv, Env) ->
    % Temporarily remove the close-on-exec flag: since these fd's are
    % part of the operation of the port, any errors are fatal and should
    % kill the OS process.
    ok = setflag(Task, ?FD_SET, fd_cloexec, unset),
    Reply = ?PRX_CALL(Task, reexec, [Argv, Env]),
    ok = setflag(Task, ?FD_SET, fd_cloexec, set),
    Reply.

%% @doc Send data to the standard input of the process
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.180.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.194.0>}
%% 3> prx:execvp(Task1, ["cat", "-n"]).
%% ok
%% 4> prx:stdin(Task1, <<"test\n">>).
%% ok
%% 5> flush().
%% Shell got {stdout,<0.194.0>,<<"     1\ttest\n">>}
%% ok
%% '''
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

%% @doc Assign a new process owner
%%
%% `call mode': the controlling process is allowed to make calls to the
%% prx process.
%%
%% `exec mode': the controlling process receives standard output and
%% standard error from the prx process
-spec controlling_process(task(), pid()) -> ok | {error, badarg}.
controlling_process(Task, Pid) ->
    gen_statem:call(Task, {controlling_process, Pid}, infinity).

%% @doc Assign a process to receive stdio
%%
%% Change the process receiving prx standard output and standard error.
%%
%% stdio/2 and controlling_process/2 can be used to transfer a prx process
%% between erlang processes without losing output when exec(3) is called:
%%
%% ~~~
%% ok = prx:stdio(Owner, NewOwner),
%% ok = prx:execvp(Owner, Argv),
%% ok = prx:controlling_process(Owner, NewOwner).
%% ~~~
-spec stdio(task(), pid()) -> ok | {error, badarg}.
stdio(Task, Pid) ->
    gen_statem:call(Task, {stdio, Pid}, infinity).

%% @doc Get the process pipeline list for the task
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.180.0>}
%% 2> prx:getpid(Task).
%% 8094
%% 3> {ok, Task1} = prx:fork(Task).
%% {ok,<0.208.0>}
%% 4> prx:getpid(Task1).
%% 8175
%% 5> {ok, Task2} = prx:fork(Task1).
%% {ok,<0.3006.0>}
%% 6> prx:getpid(Task2).
%% 27224
%% 7> prx:pipeline(Task2).
%% [8175,27224]
%% '''
-spec pipeline(task()) -> [pid_t()].
pipeline(Task) ->
    gen_statem:call(Task, pipeline, infinity).

%% @doc Get the gen_server PID for the task
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.180.0>}
%% <0.181.0>
%% '''
-spec drv(task()) -> pid().
drv(Task) ->
    gen_statem:call(Task, drv, infinity).

%% @doc Get the parent PID for the task
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.180.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.208.0>}
%% 3> prx:parent(Task).
%% noproc
%% 4> prx:parent(Task1).
%% <0.180.0>
%% '''
-spec parent(task()) -> task() | noproc.
parent(Task) ->
    try
        gen_statem:call(Task, parent, infinity)
    catch
        exit:_ ->
            noproc
    end.

%% @doc Retrieve process info for forked processes
%%
%% Retrieve the map for a child process as returned in prx:cpid/1.
%%
%% cpid/2 searches the list of a process' children for a PID (an erlang or
%% a system PID) and returns a map containing the parent's file descriptors
%% towards the child.
%%
%% @see cpid/1
-spec cpid(task(), task() | pid_t()) -> cpid() | error.
cpid(Task, Pid) when is_pid(Pid) ->
    case pidof(Pid) of
        noproc ->
            error;
        Proc ->
            cpid(Task, Proc)
    end;
cpid(Task, Pid) when is_integer(Pid) ->
    case [N || N <- prx:cpid(Task), maps:get(pid, N, false) == Pid] of
        [] ->
            error;
        [Cpid] ->
            Cpid
    end.

%% @doc Close stdin of child process
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.176.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,19048}
%% 3> prx:execvp(Task, ["cat"]).
%% ok
%% 4> prx:eof(Task, Task1).
%% ok
%% '''
-spec eof(task(), task() | pid_t()) -> ok | {error, posix()}.
eof(Task, Pid) ->
    eof(Task, Pid, stdin).

%% @doc Close stdin, stdout or stderr of child process.
%%
%% @see eof/2
-spec eof(task(), task() | pid_t(), stdin | stdout | stderr) -> ok | {error, posix()}.
eof(Task, Pid, Stdio) when Stdio == stdin; Stdio == stderr; Stdio == stdout ->
    case cpid(Task, Pid) of
        error ->
            {error, esrch};
        Child ->
            Fd = maps:get(Stdio, Child),
            close(Task, Fd)
    end.

%% @doc Test if the task has called exec(2)
%%
%% Returns `true' if the task is running in exec mode.
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.178.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.182.0>}
%% 3> prx:execed(Task1).
%% false
%% 4> prx:execvp(Task1, ["cat"]).
%% ok
%% 5> prx:execed(Task1).
%% true
%% '''
-spec execed(task()) -> boolean().
execed(Task) ->
    case sys:get_state(Task) of
        {exec_state, _} -> true;
        _ -> false
    end.

%% @doc Retrieves the system PID of the process similar to getpid(2)
%%
%% Returns the cached value for the PID of the system process. Works
%% with tasks after the task is in exec mode.
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.178.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.182.0>}
%% 3> {ok, Task2} = prx:fork(Task).
%% {ok,<0.184.0>}
%% 4> prx:execvp(Task1, ["cat"]).
%% ok
%% 5> prx:getpid(Task2).
%% 27810
%% 7> prx:pidof(Task2).
%% 27810
%% 8> prx:pidof(Task1).
%% 27809
%% '''
-spec pidof(task()) -> pid_t() | noproc.
pidof(Task) ->
    try pipeline(Task) of
        [] ->
            Drv = drv(Task),
            Port = gen_server:call(Drv, port, infinity),
            case erlang:port_info(Port) of
                undefined ->
                    noproc;
                Opt ->
                    proplists:get_value(os_pid, Opt)
            end;
        Pipeline ->
            lists:last(Pipeline)
    catch
        exit:_ ->
            noproc
    end.

%% @doc Register a function to be called at task termination.
%%
%% The atexit function runs in the parent of the process. atexit/2 must
%% use prx_drv:call/4 to manipulate the task.
%%
%% == Examples ==
%%
%% The default function closes stdin, stdout and stderr of the system
%% process:
%%
%% ```
%% fun(Drv, Pipeline, Pid) ->
%%  prx_drv:call(Drv, Pipeline, close, [maps:get(stdout, Pid)]),
%%  prx_drv:call(Drv, Pipeline, close, [maps:get(stdin, Pid)]),
%%  prx_drv:call(Drv, Pipeline, close, [maps:get(stderr, Pid)])
%% end
%% '''
-spec atexit(task(), fun((pid(), [pid_t()], cpid()) -> any())) -> ok.
atexit(Task, Fun) when is_function(Fun, 3) ->
    gen_statem:call(Task, {atexit, Fun}, infinity).

%% @doc Convenience function to fork a privileged process in the shell.
%%
%% Sets the application environment so prx can fork a privileged
%% process. `sudo' must be configured to run the prx binary.
%%
%% The application environment must be set before prx:fork/0 is called.
%%
%% Equivalent to:
%%
%% ```
%% application:set_env(prx, options, [{exec, "sudo -n"}]),
%% {ok, Task} = prx:fork(),
%% 0 = prx:getuid(Task).
%% '''
%%
%% == Examples ==
%%
%% ```
%% 1> prx:sudo().
%% ok
%% 2> {ok, Task} = prx:fork().
%% {ok,<0.199.0>}
%% 3> prx:getuid(Task).
%% 0
%% '''
-spec sudo() -> ok.
sudo() ->
    case os:type() of
        {unix, openbsd} ->
            sudo("doas");
        {unix, _} ->
            sudo("sudo -n")
    end.

%% @doc Convenience function to fork a privileged process in the shell.
%%
%% Allows specifying the command.
%%
%% == Examples ==
%%
%% For example, on OpenBSD:
%%
%% ```
%% 1> prx:sudo("doas").
%% ok
%% 2> {ok, Task} = prx:fork().
%% {ok,<0.199.0>}
%% 3> prx:getuid(Task).
%% 0
%% '''
-spec sudo(iodata()) -> ok.
sudo(Exec) ->
    Env = application:get_env(prx, options, []),
    Opt = orddict:merge(
        fun(_Key, _V1, V2) -> V2 end,
        orddict:from_list(Env),
        orddict:from_list([{exec, to_charlist(Exec)}])
    ),
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
            {ok, call_state, #state{drv = Drv, pipeline = [], owner = Owner, stdio = Owner}};
        Error ->
            {stop, Error}
    end;
init([Drv, Owner, Parent, Pipeline0, Call, Argv]) when Call == fork; Call == clone ->
    process_flag(trap_exit, true),
    case prx_drv:call(Drv, Pipeline0, Call, Argv) of
        {ok, Pipeline} ->
            {ok, call_state, #state{
                drv = Drv,
                pipeline = Pipeline,
                owner = Owner,
                stdio = Owner,
                parent = Parent
            }};
        {prx_error, Error} ->
            erlang:error(Error, [Argv]);
        {error, Error} ->
            {stop, Error}
    end.

%% @private
handle_info(
    {alcove_event, Drv, Pipeline, {exit_status, Status}},
    _StateName,
    #state{
        drv = Drv,
        pipeline = Pipeline,
        stdio = Stdio
    } = State
) ->
    Stdio ! {exit_status, self(), Status},
    {stop, shutdown, State};
handle_info(
    {alcove_event, Drv, Pipeline, {termsig, Sig}},
    _StateName,
    #state{
        drv = Drv,
        pipeline = Pipeline,
        stdio = Stdio
    } = State
) ->
    Stdio ! {termsig, self(), Sig},
    {stop, shutdown, State};
handle_info(
    {alcove_stdout, Drv, Pipeline, Buf},
    exec_state,
    #state{
        drv = Drv,
        pipeline = Pipeline,
        stdio = Stdio
    } = State
) ->
    Stdio ! {stdout, self(), Buf},
    {next_state, exec_state, State};
handle_info(
    {alcove_stderr, Drv, Pipeline, Buf},
    exec_state,
    #state{
        drv = Drv,
        pipeline = Pipeline,
        stdio = Stdio
    } = State
) ->
    Stdio ! {stderr, self(), Buf},
    {next_state, exec_state, State};
handle_info(
    {alcove_pipe, Drv, Pipeline, Bytes},
    exec_state,
    #state{
        drv = Drv,
        pipeline = Pipeline,
        stdio = Stdio
    } = State
) ->
    Stdio ! {stdin, self(), {error, {eagain, Bytes}}},
    {next_state, exec_state, State};
handle_info(
    {alcove_stdout, Drv, Pipeline, Buf},
    call_state,
    #state{
        drv = Drv,
        pipeline = Pipeline
    } = State
) ->
    error_logger:error_report({stdout, Buf}),
    {next_state, call_state, State};
handle_info(
    {alcove_stderr, Drv, Pipeline, Buf},
    call_state,
    #state{
        drv = Drv,
        pipeline = Pipeline
    } = State
) ->
    error_logger:error_report({stderr, Buf}),
    {next_state, call_state, State};
handle_info(
    {alcove_pipe, Drv, Pipeline, Bytes},
    call_state,
    #state{
        drv = Drv,
        pipeline = Pipeline,
        owner = Owner
    } = State
) ->
    Owner ! {stdin, self(), {error, {eagain, Bytes}}},
    {stop, shutdown, State};
% The process control-on-exec fd has unexpectedly closed. The process
% has probably received a signal and been terminated.
handle_info(
    {alcove_ctl, Drv, Pipeline, fdctl_closed},
    call_state,
    #state{
        drv = Drv,
        pipeline = Pipeline
    } = State
) ->
    {next_state, call_state, State};
handle_info(
    {alcove_ctl, Drv, Pipeline, Buf},
    call_state,
    #state{
        drv = Drv,
        pipeline = Pipeline
    } = State
) ->
    error_logger:error_report({ctl, Buf}),
    {next_state, call_state, State};
handle_info(
    {alcove_event, Drv, Pipeline, {signal, Signal, Info}},
    call_state,
    #state{
        drv = Drv,
        pipeline = Pipeline,
        sigaction = Sigaction,
        owner = Owner
    } = State
) ->
    case maps:find(Signal, Sigaction) of
        error ->
            Owner ! {signal, self(), Signal, Info};
        {ok, Fun} ->
            Fun(Drv, Pipeline, Signal, Info)
    end,
    {next_state, call_state, State};
handle_info(
    {alcove_event, Drv, Pipeline, Buf},
    call_state,
    #state{
        drv = Drv,
        pipeline = Pipeline
    } = State
) ->
    error_logger:error_report({event, Buf}),
    {next_state, call_state, State};
handle_info({'EXIT', Drv, Reason}, _, #state{drv = Drv} = State) ->
    error_logger:error_report({'EXIT', Drv, Reason}),
    {stop, {shutdown, Reason}, State};
handle_info(
    {'EXIT', Task, _Reason},
    call_state,
    #state{
        drv = Drv,
        pipeline = Pipeline,
        children = Child,
        atexit = Atexit
    } = State
) ->
    _ =
        case maps:find(Task, Child) of
            error ->
                ok;
            {ok, Pid} ->
                [
                    Atexit(Drv, Pipeline, cpid_to_map(X))
                 || X <- prx_drv:call(Drv, Pipeline, cpid, []), X#alcove_pid.pid =:= Pid
                ]
        end,
    {next_state, call_state, State};
handle_info(Info, Cur, State) ->
    error_logger:error_report({info, Cur, Info}),
    {next_state, Cur, State}.

%% @private
terminate(_Reason, _StateName, #state{drv = Drv, pipeline = []}) ->
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
call_state(
    {call, {Owner, _Tag} = From},
    {Call, Argv},
    #state{drv = Drv, pipeline = Pipeline, children = Child} = State
) when Call =:= fork; Call =:= clone ->
    case gen_statem:start_link(?MODULE, [Drv, Owner, self(), Pipeline, Call, Argv], []) of
        {ok, Task} ->
            [Pid | _] = lists:reverse(prx:pipeline(Task)),
            {next_state, call_state, State#state{children = maps:put(Task, Pid, Child)}, [
                {reply, From, {ok, Task}}
            ]};
        Error ->
            {next_state, call_state, State, [{reply, From, Error}]}
    end;
call_state(
    {call, {Owner, _Tag} = From},
    {Call, Argv},
    #state{
        drv = Drv,
        pipeline = Pipeline,
        owner = Owner
    } = State
) when Call =:= execvp; Call =:= execve; Call =:= fexecve ->
    case prx_drv:call(Drv, Pipeline, cpid, []) of
        [] ->
            case prx_drv:call(Drv, Pipeline, Call, Argv) of
                ok ->
                    {next_state, exec_state, State, [{reply, From, ok}]};
                Error ->
                    {next_state, call_state, State, [{reply, From, Error}]}
            end;
        [#alcove_pid{} | _] ->
            {next_state, call_state, State, [{reply, From, {error, eacces}}]}
    end;
call_state(
    {call, {Owner, _Tag} = From},
    {reexec, [{fd, FD, Argv}, Env]},
    #state{
        drv = Drv,
        pipeline = Pipeline,
        owner = Owner
    } = State
) ->
    case prx_drv:call(Drv, Pipeline, cpid, []) of
        [] ->
            Reply = prx_drv:call(Drv, Pipeline, fexecve, [FD, Argv, Env]),
            {next_state, call_state, State, [{reply, From, Reply}]};
        [#alcove_pid{} | _] ->
            {next_state, call_state, State, [{reply, From, {error, eacces}}]}
    end;
call_state(
    {call, {Owner, _Tag} = From},
    {reexec, [[Arg0 | _] = Argv, Env]},
    #state{
        drv = Drv,
        pipeline = Pipeline,
        owner = Owner
    } = State
) ->
    case prx_drv:call(Drv, Pipeline, cpid, []) of
        [] ->
            Reply = prx_drv:call(Drv, Pipeline, execve, [Arg0, Argv, Env]),
            {next_state, call_state, State, [{reply, From, Reply}]};
        [#alcove_pid{} | _] ->
            {next_state, call_state, State, [{reply, From, {error, eacces}}]}
    end;
call_state(
    {call, {Owner, _Tag} = From},
    {controlling_process, Pid},
    #state{
        owner = Owner
    } = State
) ->
    Reply =
        case is_process_alive(Pid) of
            false ->
                {error, badarg};
            true ->
                ok
        end,
    {next_state, call_state, State#state{owner = Pid, stdio = Pid}, [{reply, From, Reply}]};
call_state(
    {call, {Owner, _Tag} = From},
    {stdio, Pid},
    #state{
        owner = Owner
    } = State
) ->
    Reply =
        case is_process_alive(Pid) of
            false ->
                {error, badarg};
            true ->
                ok
        end,
    {next_state, call_state, State#state{stdio = Pid}, [{reply, From, Reply}]};
call_state(
    {call, {Owner, _Tag} = From},
    drv,
    #state{
        drv = Drv,
        owner = Owner
    } = State
) ->
    {next_state, call_state, State, [{reply, From, Drv}]};
call_state(
    {call, {Owner, _Tag} = From},
    parent,
    #state{
        parent = Parent,
        owner = Owner
    } = State
) ->
    {next_state, call_state, State, [{reply, From, Parent}]};
call_state(
    {call, {_Owner, _Tag} = From},
    pipeline,
    #state{
        pipeline = Pipeline
    } = State
) ->
    {next_state, call_state, State, [{reply, From, Pipeline}]};
%%%
%%% setcpid: handle or forward to parent
%%%

%%%% setcpid: request to port process
call_state(
    {call, {Owner, _Tag} = From},
    {setcpid, [_Opt, _Val]},
    #state{
        owner = Owner,
        parent = noproc
    } = State
) ->
    {next_state, call_state, State, [{reply, From, false}]};
%%% setcpid: forward call to parent
call_state(
    {call, {Owner, _Tag} = From},
    {setcpid, [Opt, Val]},
    #state{
        owner = Owner,
        parent = Parent
    } = State
) ->
    Reply = prx:setcpid(Parent, Opt, Val),
    {next_state, call_state, State, [{reply, From, Reply}]};
%%% setcpid: parent modifies child state
call_state(
    {call, {Owner, _Tag} = From},
    {setcpid, [Pid, Opt, Val]},
    #state{
        owner = Owner,
        drv = Drv,
        pipeline = Pipeline
    } = State
) ->
    Reply = prx_drv:call(Drv, Pipeline, setcpid, [Pid, Opt, Val]),
    {next_state, call_state, State, [{reply, From, Reply}]};
%%% setcpid: handle request to modify child state
call_state(
    {call, {Child, _Tag} = From},
    {setcpid, [Opt, Val]},
    #state{
        children = Children,
        drv = Drv,
        pipeline = Pipeline
    } = State
) ->
    Reply =
        case maps:find(Child, Children) of
            error ->
                false;
            {ok, Pid} ->
                prx_drv:call(Drv, Pipeline, setcpid, [Pid, Opt, Val])
        end,
    {next_state, call_state, State, [{reply, From, Reply}]};
%%%
%%% getcpid: handle or forward to parent
%%%

%%%% getcpid: request to port process
call_state(
    {call, {Owner, _Tag} = From},
    {getcpid, [_Opt]},
    #state{
        owner = Owner,
        parent = noproc
    } = State
) ->
    {next_state, call_state, State, [{reply, From, false}]};
%%% getcpid: forward call to parent
call_state(
    {call, {Owner, _Tag} = From},
    {getcpid, [Opt]},
    #state{
        owner = Owner,
        parent = Parent
    } = State
) ->
    Reply = prx:getcpid(Parent, Opt),
    {next_state, call_state, State, [{reply, From, Reply}]};
%%% getcpid: request from owner for child state
call_state(
    {call, {Owner, _Tag} = From},
    {getcpid, [Pid, Opt]},
    #state{
        owner = Owner,
        drv = Drv,
        pipeline = Pipeline
    } = State
) ->
    Cpid = [
        cpid_to_map(N)
     || N <- prx_drv:call(Drv, Pipeline, cpid, []),
        N#alcove_pid.pid == Pid
    ],
    Reply =
        case Cpid of
            [] -> false;
            [X] -> maps:get(Opt, X, false)
        end,
    {next_state, call_state, State, [{reply, From, Reply}]};
%%% getcpid: parent handles request by child
call_state(
    {call, {Child, _Tag} = From},
    {getcpid, [Opt]},
    #state{
        children = Children,
        drv = Drv,
        pipeline = Pipeline
    } = State
) ->
    Cpid =
        case maps:find(Child, Children) of
            error ->
                [];
            {ok, Pid} ->
                [
                    cpid_to_map(N)
                 || N <- prx_drv:call(Drv, Pipeline, cpid, []),
                    N#alcove_pid.pid == Pid
                ]
        end,
    Reply =
        case Cpid of
            [] -> false;
            [X] -> maps:get(Opt, X, false)
        end,
    {next_state, call_state, State, [{reply, From, Reply}]};
call_state(
    {call, {Owner, _Tag} = From},
    {atexit, Fun},
    #state{
        owner = Owner
    } = State
) ->
    {next_state, call_state, State#state{atexit = Fun}, [{reply, From, ok}]};
call_state(
    {call, {Owner, _Tag} = From},
    {sigaction, Signal, Fun},
    #state{
        sigaction = Sigaction,
        owner = Owner
    } = State
) ->
    {next_state, call_state,
        State#state{
            sigaction = maps:put(Signal, Fun, Sigaction)
        },
        [{reply, From, ok}]};
% port process calls exit
call_state(
    {call, {Owner, _Tag} = From},
    {exit, _},
    #state{
        drv = Drv,
        owner = Owner,
        pipeline = []
    } = State
) ->
    case prx_drv:call(Drv, [], cpid, []) of
        [] ->
            {stop_and_reply, shutdown, [{reply, From, ok}]};
        [#alcove_pid{} | _] ->
            {next_state, call_state, State, [{reply, From, {error, eacces}}]}
    end;
call_state(
    {call, {Owner, _Tag} = From},
    {Call, Argv},
    #state{
        drv = Drv,
        pipeline = Pipeline,
        owner = Owner
    } = State
) ->
    Reply = prx_drv:call(Drv, Pipeline, Call, Argv),
    {next_state, call_state, State, [{reply, From, Reply}]};
call_state({call, From}, _, State) ->
    {next_state, call_state, State, [{reply, From, {prx_error, eacces}}]};
call_state(info, Event, State) ->
    handle_info(Event, call_state, State).

%% @private
exec_state(cast, {stdin, Buf}, #state{drv = Drv, pipeline = Pipeline} = State) ->
    prx_drv:stdin(Drv, Pipeline, Buf),
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

%%%
%%% setcpid: forward call to parent
%%%

%%% setcpid: forward call to parent
exec_state(
    {call, {Owner, _Tag} = From},
    {setcpid, [Opt, Val]},
    #state{
        owner = Owner,
        parent = Parent
    } = State
) ->
    Reply = prx:setcpid(Parent, Opt, Val),
    {next_state, exec_state, State, [{reply, From, Reply}]};
%%% getcpid: forward call to parent
exec_state(
    {call, {Owner, _Tag} = From},
    {getcpid, [Opt]},
    #state{
        owner = Owner,
        parent = Parent
    } = State
) ->
    Reply = prx:getcpid(Parent, Opt),
    {next_state, exec_state, State, [{reply, From, Reply}]};
exec_state(
    {call, From},
    pipeline,
    #state{
        pipeline = Pipeline
    } = State
) ->
    {next_state, exec_state, State, [{reply, From, Pipeline}]};
exec_state(
    {call, From},
    parent,
    #state{
        parent = Parent
    } = State
) ->
    {next_state, exec_state, State, [{reply, From, Parent}]};
exec_state(
    {call, {Owner, _Tag} = From},
    {controlling_process, Pid},
    #state{
        owner = Owner
    } = State
) ->
    Reply =
        case is_process_alive(Pid) of
            false ->
                {error, badarg};
            true ->
                ok
        end,
    {next_state, exec_state, State#state{owner = Pid, stdio = Pid}, [{reply, From, Reply}]};
exec_state(
    {call, {Owner, _Tag} = From},
    {stdio, Pid},
    #state{
        owner = Owner
    } = State
) ->
    Reply =
        case is_process_alive(Pid) of
            false ->
                {error, badarg};
            true ->
                ok
        end,
    {next_state, exec_state, State#state{stdio = Pid}, [{reply, From, Reply}]};
exec_state({call, From}, _, State) ->
    {next_state, exec_state, State, [{reply, From, {prx_error, eacces}}]};
exec_state(info, Event, State) ->
    handle_info(Event, exec_state, State).

%%%===================================================================
%%% Internal functions
%%%===================================================================

to_charlist(S) ->
    erlang:binary_to_list(erlang:iolist_to_binary(S)).

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
    Stdout =
        case Reply of
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
    _ =
        case is_process_alive(Task) of
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
            flush_stdio(Task, Child, [Buf | Acc], Timeout);
        {stderr, Child, Buf} ->
            flush_stdio(Task, Child, [Buf | Acc], Timeout);
        {exit_status, Child, _} ->
            flush_stdio(Task, Child, Acc, 0);
        {termsig, Child, _} ->
            flush_stdio(Task, Child, Acc, 0);
        {exit_status, Task, _} ->
            flush_stdio(Task, Child, Acc, 0);
        {termsig, Task, _} ->
            flush_stdio(Task, Child, Acc, 0)
    after Timeout -> list_to_binary(lists:reverse(Acc))
    end.

setflag(_Task, [], _Flag, _Status) ->
    ok;
setflag(Task, [FD | FDSet], Flag, Status) ->
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

getopts(Task) ->
    % Required for prx so reset to defaults: stdin_closed, stdout_closed,
    % stderr_closed
    Opts = [exit_status, flowcontrol, maxforkdepth, termsig, signaloneof],

    [{N, prx:getopt(Task, N)} || N <- Opts].

setopts(Task, Opts) ->
    [true = prx:setopt(Task, Key, Val) || {Key, Val} <- Opts].

%%%===================================================================
%%% Exported functions
%%%===================================================================

%% @doc setproctitle(3): set the process title
%%
%% Set the process title displayed in utilities like ps(1) by overwriting
%% the command's arg0.
%%
%% Linux systems may also want to set the command name using `prctl/6':
%%
%% ```
%% prx:prctl(Task, pr_set_name, <<"newname">>, 0, 0, 0)
%% '''
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.177.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,28210}
%% 3> prx:setproctitle(Task1, "new process name").
%% ok
%% '''
%%
%% @see prctl/6
-spec setproctitle(task(), iodata()) -> ok.
setproctitle(Task, Name) ->
    case os:type() of
        {unix, sunos} ->
            ok;
        {unix, OS} when
            OS =:= linux; OS =:= freebsd; OS =:= openbsd; OS =:= netbsd; OS =:= darwin
        ->
            ?PRX_CALL(Task, setproctitle, [Name]);
        _ ->
            ok
    end.

%% @doc Returns the list of child PIDs for this process.
%%
%% Each child task is a map composed of:
%%
%%  • pid: system pid
%%
%%  • exec: true if the child has called exec()
%%
%%  • fdctl: parent end of CLOEXEC file descriptor used to monitor if the child process has called exec()
%%
%%  • stdin: parent end of the child process' standard input
%%
%%  • stdout: parent end of the child process' standard output
%%
%%  • stderr: parent end of the child process' standard error
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.178.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.182.0>}
%% 3> {ok, Task2} = prx:fork(Task).
%% {ok,<0.184.0>}
%% 4> prx:cpid(Task).
%% [#{exec => true,fdctl => -2,flowcontrol => -1,pid => 27809,
%%    signaloneof => 15,stderr => 13,stdin => 10,stdout => 11},
%%  #{exec => false,fdctl => 9,flowcontrol => -1,pid => 27810,
%%    signaloneof => 15,stderr => 17,stdin => 14,stdout => 15}]
%% '''
-spec cpid(task()) -> [cpid()].
cpid(Task) ->
    [cpid_to_map(Pid) || Pid <- ?PRX_CALL(Task, cpid, [])].

cpid_to_map(#alcove_pid{
    pid = Pid,
    flowcontrol = Flowcontrol,
    signaloneof = Signaloneof,
    fdctl = Ctl,
    stdin = In,
    stdout = Out,
    stderr = Err
}) ->
    #{
        pid => Pid,
        exec => Ctl =:= -2,
        flowcontrol => Flowcontrol,
        signaloneof => Signaloneof,
        fdctl => Ctl,
        stdin => In,
        stdout => Out,
        stderr => Err
    }.

%% @doc getrlimit(2): retrieve the resource limits for a process
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.158.0>}
%% 2> prx:getrlimit(Task, rlimit_nofile).
%% {ok,#{cur => 1024,max => 1048576}}
%% '''
-spec getrlimit(task(), constant()) ->
    {ok, #{cur => uint64_t(), max => uint64_t()}} | {error, posix()}.
getrlimit(Task, Resource) ->
    case ?PRX_CALL(Task, getrlimit, [Resource]) of
        {ok, #alcove_rlimit{cur = Cur, max = Max}} ->
            {ok, #{cur => Cur, max => Max}};
        Error ->
            Error
    end.

%% @doc setrlimit(2): set a resource limit
%%
%% Note on `rlimit_nofile':
%%
%% The control process requires a fixed number of file descriptors for
%% each subprocess. Reducing the number of file descriptors will reduce
%% the limit on child processes.
%%
%% If the file descriptor limit is below the number of file descriptors
%% currently used, setrlimit/4,5 will return `{error, einval}'.
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.158.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.162.0>}
%% 3> prx:getrlimit(Task1, rlimit_nofile).
%% {ok,#{cur => 1048576,max => 1048576}}
%% 4> prx:setrlimit(Task1, rlimit_nofile, #{cur => 64, max => 64}).
%% ok
%% 5> prx:getrlimit(Task1, rlimit_nofile).
%% {ok,#{cur => 64,max => 64}}
%% 6> prx:getrlimit(Task, rlimit_nofile).
%% {ok,#{cur => 1048576,max => 1048576}}
%% '''
-spec setrlimit(task(), constant(), #{cur => uint64_t(), max => uint64_t()}) ->
    ok | {error, posix()}.
setrlimit(Task, Resource, Limit) ->
    #{cur := Cur, max := Max} = Limit,
    ?PRX_CALL(Task, setrlimit, [Resource, #alcove_rlimit{cur = Cur, max = Max}]).

%% @doc select(2): poll a list of file descriptor for events
%%
%% select/5 will block until an event occurs on a file descriptor, a timeout
%% is reached or interrupted by a signal.
%%
%% The Timeout value may be:
%%
%% • an empty list ([]): causes select to block indefinitely (no timeout)
%%
%% • a map indicating the timeout
%%
%% The map contains these fields:
%%
%% • sec : number of seconds to wait
%%
%% • usec : number of microseconds to wait
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.178.0>}
%% 2> {ok, FD} = prx:open(Task, "/dev/null", [o_rdwr], 0).
%% {ok,7}
%% 3> prx:select(Task, [FD], [FD], [FD], []).
%% {ok,[7],[7],[]}
%% 4> prx:select(Task, [FD], [FD], [FD], #{sec => 1, usec => 1}).
%% {ok,[7],[7],[]}
%% '''
-spec select(
    task(),
    Readfds :: [fd()],
    Writefds :: [fd()],
    Exceptfds :: [fd()],
    Timeval :: [] | #{sec => int64_t(), usec => int64_t()}
) -> {ok, [fd()], [fd()], [fd()]} | {error, posix()}.
select(Task, Readfds, Writefds, Exceptfds, Timeout) when is_map(Timeout) ->
    Sec = maps:get(sec, Timeout, 0),
    Usec = maps:get(usec, Timeout, 0),
    ?PRX_CALL(Task, select, [Readfds, Writefds, Exceptfds, #alcove_timeval{sec = Sec, usec = Usec}]);
select(Task, Readfds, Writefds, Exceptfds, Timeout) ->
    ?PRX_CALL(Task, select, [Readfds, Writefds, Exceptfds, Timeout]).

%% @doc cap_enter(2): place process into capability mode
%%
%% == Support ==
%%
%% • FreeBSD
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.154.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.158.0>}
%% 3> prx:cap_enter(Task1).
%% ok
%% 4> prx:kill(Task1, 0, 0).
%% {error,ecapmode}
%% 5> prx:kill(Task, 0, 0).
%% ok
%% '''
-spec cap_enter(task()) -> ok | {error, posix()}.
cap_enter(Task) ->
    ?PRX_CALL(Task, cap_enter, []).

%% @doc cap_fcntls_get(2): get allowed fcntl commands in capability mode
%%
%% == Support ==
%%
%% • FreeBSD
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.154.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.165.0>}
%% 3> {ok, FD} = prx:open(Task1, "/etc/passwd", [o_rdonly]).
%% {ok,7}
%% 4> prx:cap_enter(Task1).
%% ok
%% 5> prx:cap_fcntls_get(Task1, FD).
%% {ok,120}
%% '''
-spec cap_fcntls_get(task(), fd()) -> {ok, int32_t()} | {error, posix()}.
cap_fcntls_get(Task, FD) ->
    ?PRX_CALL(Task, cap_fcntls_get, [FD]).

%% @doc cap_fcntls_limit(2): manage fcntl commands in capability mode
%%
%% == Support ==
%%
%% • FreeBSD
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.154.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.165.0>}
%% 3> {ok, FD} = prx:open(Task1, "/etc/passwd", [o_rdonly]).
%% {ok,7}
%% 4> prx:cap_enter(Task1).
%% ok
%% 5> prx:cap_fcntls_get(Task1, FD).
%% {ok,120}
%% 6> prx:cap_fcntls_limit(Task1, FD, [cap_fcntl_setfl]).
%% ok
%% 7> prx:cap_fcntls_get(Task1, FD).
%% {ok,16}
%% '''
-spec cap_fcntls_limit(task(), fd(), [constant()]) -> ok | {error, posix()}.
cap_fcntls_limit(Task, FD, Rights) ->
    ?PRX_CALL(Task, cap_fcntls_limit, [FD, Rights]).

%% @doc cap_getmode(2): check if capability mode is enabled
%%
%% • `0' : false
%%
%% • `1' : true
%%
%% == Support ==
%%
%% • FreeBSD
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.154.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.165.0>}
%% 3> prx:cap_enter(Task1).
%% ok
%% 4> prx:cap_getmode(Task).
%% {ok,0}
%% 5> prx:cap_getmode(Task1).
%% {ok,1}
%% '''
-spec cap_getmode(task()) -> {ok, 0 | 1} | {error, posix()}.
cap_getmode(Task) ->
    ?PRX_CALL(Task, cap_getmode, []).

%% @doc cap_ioctls_limit(2): manage allowed ioctl commands
%%
%% == Support ==
%%
%% • FreeBSD
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.154.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.158.0>}
%% 3> {ok, FD} = prx:open(Task1, "/dev/pts/1", [o_rdwr, o_nonblock]).
%% {ok,7}
%% 4> prx:cap_enter(Task1).
%% ok
%% 5> prx:cap_ioctls_limit(Task1, FD, [tiocmget, tiocgwinsz]).
%% ok
%% 6> prx:ioctl(Task1, FD, tiocmset, <<>>).
%% {error,enotcapable}
%% 7> prx:ioctl(Task1, FD, tiocmget, <<>>).
%% {ok,#{arg => <<>>,return_value => 0}}
%% '''
-spec cap_ioctls_limit(task(), fd(), [constant()]) -> ok | {error, posix()}.
cap_ioctls_limit(Task, FD, Rights) ->
    ?PRX_CALL(Task, cap_ioctls_limit, [FD, Rights]).

%% @doc cap_rights_limit(2): manage process capabilities
%%
%% == Support ==
%%
%% • FreeBSD
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.154.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.168.0>}
%% 3> {ok, FD} = prx:open(Task1, "/etc/passwd", [o_rdonly]).
%% {ok,7}
%% 4> prx:cap_enter(Task1).
%% ok
%% 5> prx:cap_rights_limit(Task1, FD, [cap_read]).
%% ok
%% 6> prx:read(Task1, FD, 64).
%% {ok,<<"# $FreeBSD$\n#\nroot:*:0:0:Charlie &:/root:/bin/csh\ntoor:*:0:0:Bou">>}
%% 7> prx:lseek(Task1, FD, 0, 0).
%% {error,enotcapable}
%% 8> prx:open(Task1, "/etc/passwd", [o_rdonly]).
%% {error,ecapmode}
%% '''
-spec cap_rights_limit(task(), fd(), [constant()]) -> ok | {error, posix()}.
cap_rights_limit(Task, FD, Rights) ->
    ?PRX_CALL(Task, cap_rights_limit, [FD, Rights]).

%% @doc chdir(2): change process current working directory
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.154.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.178.0>}
%% 3> prx:chdir(Task, "/").
%% ok
%% 4> prx:chdir(Task1, "/tmp").
%% ok
%% 5> prx:getcwd(Task).
%% {ok,<<"/">>}
%% 6> prx:getcwd(Task1).
%% {ok,<<"/tmp">>}
%% '''
-spec chdir(task(), iodata()) -> ok | {error, posix()}.
chdir(Task, Path) ->
    ?PRX_CALL(Task, chdir, [Path]).

%% @doc chmod(2): change file permissions
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.154.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.178.0>}
%% 3> {ok, FD} = prx:open(Task1, "/tmp/testfile.txt", [o_wronly, o_creat], 8#644).
%% {ok,7}
%% 4> prx:chmod(Task1, "/tmp/testfile.txt", 8#400).
%% ok
%% '''
-spec chmod(task(), iodata(), mode_t()) -> ok | {error, posix()}.
chmod(Task, Path, Mode) ->
    ?PRX_CALL(Task, chmod, [Path, Mode]).

%% @doc chown(2): change file ownership
%%
%% == Examples ==
%%
%% ```
%% 1> prx:sudo().
%% ok
%% 2> {ok, Task} = prx:fork().
%% {ok,<0.155.0>}
%% 3> {ok, Task1} = prx:fork(Task).
%% {ok,<0.159.0>}
%% 4> {ok, FD} = prx:open(Task1, "/tmp/testfile.txt", [o_wronly, o_creat], 8#644).
%% {ok,7}
%% 5> prx:chown(Task1, "/tmp/testfile.txt", 0, 0).
%% ok
%% '''
-spec chown(task(), iodata(), uid_t(), gid_t()) -> ok | {error, posix()}.
chown(Task, Path, Owner, Group) ->
    ?PRX_CALL(Task, chown, [Path, Owner, Group]).

%% @doc chroot(2): change root directory
%%
%% == Examples ==
%%
%% ```
%% 1> prx:sudo().
%% ok
%% 2> {ok, Task} = prx:fork().
%% {ok,<0.155.0>}
%% 3> {ok, Task1} = prx:fork(Task).
%% {ok,<0.159.0>}
%% 4> prx:chroot(Task1, "/tmp").
%% ok
%% 5> prx:chdir(Task1, "/").
%% ok
%% 6> prx:getcwd(Task1).
%% {ok,<<"/">>}
%% '''
-spec chroot(task(), iodata()) -> ok | {error, posix()}.
chroot(Task, Path) ->
    ?PRX_CALL(Task, chroot, [Path]).

%% @doc clearenv(3): zero process environment
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.155.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.159.0>}
%% 3> prx:clearenv(Task1).
%% ok
%% 4> prx:environ(Task1).
%% []
%% '''
-spec clearenv(task()) -> ok | {error, posix()}.
clearenv(Task) ->
    ?PRX_CALL(Task, clearenv, []).

%% @doc close(2): close a file descriptor
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.154.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.178.0>}
%% 3> {ok, FD} = prx:open(Task1, "/tmp/testfile.txt", [o_wronly, o_creat], 8#644).
%% {ok,7}
%% 4> prx:close(Task1, FD).
%% ok
%% '''
-spec close(task(), fd()) -> ok | {error, posix()}.
close(Task, FD) ->
    ?PRX_CALL(Task, close, [FD]).

%% @doc environ(7): return the process environment variables
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.154.0>}
%% 2> prx:environ(Task).
%% [<<"LANG=C.UTF-8">>,
%%  <<"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin">>,
%%  <<"TERM=screen">>, <<"SHELL=/bin/bash">>]
%% '''
-spec environ(task()) -> [binary()].
environ(Task) ->
    ?PRX_CALL(Task, environ, []).

%% @doc exit(3): cause an prx control process to exit
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.154.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.178.0>}
%% 3> prx:exit(Task1, 111).
%% ok
%% 4> flush().
%% Shell got {exit_status,<0.159.0>,111}
%% ok
%% '''
-spec exit(task(), int32_t()) -> ok.
exit(Task, Status) ->
    ?PRX_CALL(Task, exit, [Status]).

%% @doc fcntl(2) : perform operation on a file descriptor
%%
%% @see fcntl/4
-spec fcntl(task(), fd(), constant()) -> {ok, int64_t()} | {error, posix()}.
fcntl(Task, FD, Cmd) ->
    ?PRX_CALL(Task, fcntl, [FD, Cmd, 0]).

%% @doc fcntl(2): perform operations on a file descriptor with argument
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.178.0>}
%% 2> Stdin = 0.
%% 0
%% 3> prx:fcntl(Task, Stdin, f_getfd, 0).
%% {ok,0}
%% '''
-spec fcntl(task(), fd(), constant(), int64_t()) -> {ok, int64_t()} | {error, posix()}.
fcntl(Task, FD, Cmd, Arg) ->
    ?PRX_CALL(Task, fcntl, [FD, Cmd, Arg]).

%% @doc filter/2 : restrict control process calls
%%
%% Restricts the set of calls available to a prx control process. If fork
%% is allowed, any subsequently forked control processes inherit the set
%% of filtered calls:
%%
%% ```
%% {ok, Ctrl} = prx:fork(),
%% ok = prx:filter(Ctrl, [getpid]),
%% {ok, Task} = prx:fork(Ctrl),
%%
%% {'EXIT', {undef, _}} = (catch prx:getpid(Task)).
%% '''
%%
%% @see filter/3
-spec filter(task(), [call()] | {allow, [call()]} | {deny, [call()]}) -> ok.
filter(Task, Calls) ->
    filter(Task, Calls, Calls).

%% @doc filter/3 : restrict control process and subprocess calls
%%
%% filter/3 specifies the set of calls available to a prx control process
%% and any subsequently forked control processes. Control processes continue
%% to proxy data and monitor and reap subprocesses.
%%
%% Invoking a filtered call will crash the process with 'undef'.
%%
%% If the filter/3 call is filtered, subsequent calls to filter/3
%% will fail.
%%
%% Calls can be either allowed or denied. If a call is allowed, all
%% other calls are filtered.
%%
%% Once a filter for a call is added, the call cannot be removed from
%% the filter set. Passing an empty list ([]) specifies the current filter
%% set should not be modified.
%%
%% ```
%% % the set of calls to filter, any forked control subprocesses
%% % are unrestricted
%% prx:filter(Task, {deny, [getpid, execve, execvp]}, [])
%%
%% % equivalent to {deny, [getpid, execve, execvp]}
%% prx:filter(Task, [getpid, execve, execvp], [])
%%
%% % all other calls are filtered including filter
%% prx:filter(Task, {allow, [fork, clone, kill]}, [])
%%
%% % init: control process can fork, subprocesses can exec a data process
%% prx:filter(Task, {allow, [fork, clone, kill]}, {allow, [execve, execvp]})
%% '''
%%
%% == Examples ==
%%
%% ```
%% 1> catch_exception(true).
%% false
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.178.0>}
%% %% % Control process: restricted to: fork, filter, getcwd
%% %% % Any forked control subprocess: restricted to: getpid, gethostname
%% 2> prx:filter(Task, {allow, [fork, filter, getcwd]}, {allow, [getpid, gethosname]}).
%% ok
%% 3> {ok, Task1} = prx:fork(Task).
%% {ok,<0.190.0>}
%% 4> prx:getpid(Task).
%% * exception error: undefined function prx:getpid/1
%% 5> prx:getcwd(Task1).
%% * exception error: undefined function prx:getcwd/1
%% 6> prx:getcwd(Task).
%% {ok,<<"/">>}
%% '''
-spec filter(
    task(),
    [call()] | {allow, [call()]} | {deny, [call()]},
    [call()] | {allow, [call()]} | {deny, [call()]}
) -> ok.
filter(Task, Calls, SubprocessCalls) ->
    ?PRX_CALL(Task, filter, [to_filter(Calls), to_filter(SubprocessCalls)]).

-spec to_filter([call()] | {allow, [call()]} | {deny, [call()]}) -> binary().
to_filter(Calls) when is_list(Calls) ->
    alcove:filter(Calls);
to_filter({allow, Calls}) ->
    alcove:filter({allow, substitute_calls(Calls)});
to_filter({deny, Calls}) ->
    alcove:filter({deny, Calls}).

substitute_calls(Calls) ->
    proplists:normalize(Calls, [
        {aliases, [
            {replace_process_image, reexec}
        ]},
        {expand, [
            {reexec, [
                cpid,
                environ,
                execve,
                fcntl,
                fcntl_constant,
                fexecve,
                getopt,
                setcpid,
                setopt
            ]},
            {fork, [cpid, fork, close]},
            {clone, [cpid, clone, close]},
            {execve, [cpid, execve]},
            {fexecve, [cpid, fexecve]},
            {execvp, [cpid, execvp]},
            {getcpid, []}
        ]}
    ]).

%% @doc Get control process attributes
%%
%% Retrieve attributes set by the prx control process %% for a child
%% process.
%%
%% @see getcpid/3
-spec getcpid(task(), atom()) -> int32_t() | false.
getcpid(Task, Opt) ->
    try
        ?PRX_CALL(Task, getcpid, [Opt])
    catch
        exit:_ ->
            false
    end.

%% @doc Get control process attributes
%%
%% Retrieves attributes set by the prx control process for a
%% child process.
%%
%% • flowcontrol
%%
%%   Number of messages allowed from process:
%%
%%         -1 : flowcontrol disabled
%%
%%         0 : stdout/stderr for process is not read
%%
%%         1+ : read this many messages from the process
%%
%% • signaloneof
%%
%%   Signal sent to child process on shutdown.
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.154.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.178.0>}
%% 3> prx:getcpid(Task, Task1, flowcontrol).
%% -1
%% '''
-spec getcpid(task(), task() | cpid() | pid_t(), atom()) -> int32_t() | false.
getcpid(Task, Pid, Opt) when is_pid(Pid) ->
    case pidof(Pid) of
        noproc ->
            false;
        Proc ->
            getcpid(Task, Proc, Opt)
    end;
getcpid(Task, Pid, Opt) when is_integer(Pid) ->
    ?PRX_CALL(Task, getcpid, [Pid, Opt]).

%% @doc getcwd(3): return the current working directory
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.179.0>}
%% 2> prx:chdir(Task, "/").
%% ok
%% 3> prx:getcwd(Task).
%% {ok,<<"/">>}
%% '''
-spec getcwd(task()) -> {ok, binary()} | {error, posix()}.
getcwd(Task) ->
    ?PRX_CALL(Task, getcwd, []).

%% @doc getenv(3): retrieve an environment variable
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.179.0>}
%% 2> prx:chdir(Task, "/").
%% ok
%% 6> prx:getenv(Task, "TERM").
%% <<"screen">>
%% '''
-spec getenv(task(), iodata()) -> binary() | 'false'.
getenv(Task, Name) ->
    ?PRX_CALL(Task, getenv, [Name]).

%% @doc getgid(2): retrieve the process group ID
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.179.0>}
%% 2> prx:getgid(Task).
%% 1000
%% '''
-spec getgid(task()) -> gid_t().
getgid(Task) ->
    ?PRX_CALL(Task, getgid, []).

%% @doc getgroups(2): retrieve the list of supplementary groups
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.179.0>}
%% 2> prx:getgroups(Task).
%% {ok,[24,20,1000]}
%% '''
-spec getgroups(task()) -> {ok, [gid_t()]} | {error, posix()}.
getgroups(Task) ->
    ?PRX_CALL(Task, getgroups, []).

%% @doc gethostname(2): retrieve the system hostname
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.179.0>}
%% 2> prx:gethostname(Task).
%% {ok,<<"host1">>}
%% '''
-spec gethostname(task()) -> {ok, binary()} | {error, posix()}.
gethostname(Task) ->
    ?PRX_CALL(Task, gethostname, []).

%% @doc Retrieve port options for event loop
%%
%% Options are configurable per process, with the default settings inherited
%% from the parent.
%%
%% • maxchild : non_neg_integer() : 64
%%
%%   Number of child processes allowed for this control process. The value
%%   can be modified using setopt/4,5. Additionally, reducing RLIMIT_NOFILE
%%   for the process may result in a reduced maxchild value.
%%
%% • exit_status : 1 | 0 : 1
%%
%%   Controls whether the controlling Erlang process is informed of a
%%   process exit value.
%%
%% • maxforkdepth : non_neg_integer() : 16
%%
%%   Sets the maximum length of the prx process pipeline.
%%
%% • termsig : 1 | 0 : 1
%%
%%   If a child process exits because of a signal, notify the controlling
%%   Erlang process.
%%
%% • flowcontrol : int32_t() : -1 (disabled)
%%
%%   Sets the default flow control behaviour for a newly forked process. Flow
%%   control is applied after the child process calls exec().
%%
%%   See setcpid/5.
%%
%% • signaloneof : 0-255 : 15
%%
%%   Send a signal to a child process on shutdown (stdin of the prx
%%   control process is closed).
%%
%%   See setcpid/5.
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.179.0>}
%% 2> prx:getopt(Task, maxchild).
%% 64
%% '''
-spec getopt(task(), prx_opt()) -> 'false' | int32_t().
getopt(Task, Opt) ->
    ?PRX_CALL(Task, getopt, [Opt]).

%% @doc getpgrp(2): retrieve the process group
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.179.0>}
%% 2> prx:getpgrp(Task).
%% 3924
%% '''
-spec getpgrp(task()) -> pid_t().
getpgrp(Task) ->
    ?PRX_CALL(Task, getpgrp, []).

%% @doc getpid(2): retrieve the system PID of the process
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.179.0>}
%% 2> prx:getpid(Task).
%% 3924
%% '''
-spec getpid(task()) -> pid_t().
getpid(Task) ->
    ?PRX_CALL(Task, getpid, []).

%% @doc getpriority(2): retrieve scheduling priority of process, process group or user
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.179.0>}
%% 2> prx:getpriority(Task).
%% {ok,0}
%% '''
-spec getpriority(task(), constant(), int32_t()) -> {ok, int32_t()} | {error, posix()}.
getpriority(Task, Which, Who) ->
    ?PRX_CALL(Task, getpriority, [Which, Who]).

%% @doc getresgid(2): get real, effective and saved group ID
%%
%% == Support ==
%%
%% • Linux
%%
%% • OpenBSD
%%
%% • FreeBSD
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.179.0>}
%% 2> prx:getresgid(Task).
%% {ok,1000,1000,1000}
%% '''
-spec getresgid(task()) -> {ok, gid_t(), gid_t(), gid_t()} | {error, posix()}.
getresgid(Task) ->
    ?PRX_CALL(Task, getresgid, []).

%% @doc getresuid(2): get real, effective and saved user ID
%%
%% == Support ==
%%
%% • Linux
%%
%% • OpenBSD
%%
%% • FreeBSD
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.179.0>}
%% 2> prx:getresuid(Task).
%% {ok,1000,1000,1000}
%% '''
-spec getresuid(task()) -> {ok, uid_t(), uid_t(), uid_t()} | {error, posix()}.
getresuid(Task) ->
    ?PRX_CALL(Task, getresuid, []).

%% @doc getsid(2): retrieve the session ID
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.179.0>}
%% 2> prx:getsid(Task).
%% {ok,3924}
%% '''
-spec getsid(task(), pid_t()) -> {ok, pid_t()} | {error, posix()}.
getsid(Task, OSPid) ->
    ?PRX_CALL(Task, getsid, [OSPid]).

%% @doc getuid(2): returns the process user ID
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.179.0>}
%% 2> prx:getuid(Task).
%% 1000
%% '''
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
%% • return_value: an integer equal to the return value of the ioctl.
%%
%%   Usually 0, however some ioctl's on Linux use the return
%%   value as the output parameter.
%%
%% • arg: the value depends on the type of the input parameter Argp.
%%
%% • cstruct: contains the contents of the memory pointed to by Argp
%%
%% • integer/binary: an empty binary
%%
%% == Examples ==
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
-spec ioctl(task(), fd(), constant(), cstruct()) ->
    {ok, #{return_value := integer(), arg := iodata()}} | {error, posix()}.
ioctl(Task, FD, Request, Argp) ->
    case ?PRX_CALL(Task, ioctl, [FD, Request, Argp]) of
        {ok, ReturnValue, Arg} ->
            {ok, #{return_value => ReturnValue, arg => Arg}};
        Error ->
            Error
    end.

%% @doc jail(2): restrict the current process in a system jail
%%
%% == Support ==
%%
%% • FreeBSD
%%
%% == Examples ==
%%
%% ```
%% 1> prx:sudo().
%% ok
%% 2> {ok, Task} = prx:fork().
%% {ok,<0.155.0>}
%% 3> {ok, Task1} = prx:fork(Task).
%% {ok,<0.159.0>}
%% 4> prx:jail(Task1, #{path => "/rescue", hostname => "test0", jailname => "test0"}).
%% {ok,23223}
%% 5> prx:gethostname(Task1).
%% {ok,<<"test0">>}
%% '''
-spec jail(
    task(),
    #{
        version => alcove:uint32_t(),
        path => iodata(),
        hostname => iodata(),
        jailname => iodata(),
        ip4 => [inet:ip4_address()],
        ip6 => [inet:ip6_address()]
    }
    | cstruct()
) -> {ok, int32_t()} | {error, posix()}.
jail(Task, Jail) when is_map(Jail) ->
    jail(Task, alcove_cstruct:jail(map_to_jail(Jail)));
jail(Task, Jail) ->
    ?PRX_CALL(Task, jail, [Jail]).

jail_to_map(#alcove_jail{
    version = Version,
    path = Path,
    hostname = Hostname,
    jailname = Jailname,
    ip4 = IP4,
    ip6 = IP6
}) ->
    #{
        version => Version,
        path => Path,
        hostname => Hostname,
        jailname => Jailname,
        ip4 => IP4,
        ip6 => IP6
    }.

map_to_jail(Map0) ->
    #{
        version := Version,
        path := Path,
        hostname := Hostname,
        jailname := Jailname,
        ip4 := IP4,
        ip6 := IP6
    } = maps:merge(jail_to_map(#alcove_jail{}), Map0),
    #alcove_jail{
        version = Version,
        path = Path,
        hostname = Hostname,
        jailname = Jailname,
        ip4 = IP4,
        ip6 = IP6
    }.

%% @doc kill(2): terminate a process
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.154.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.158.0>}
%% 3> Pid = prx:getpid(Task1).
%% 70524
%% 4> prx:kill(Task, 0, 0).
%% ok
%% 5> prx:kill(Task, 12345, 0).
%% {error,esrch}
%% 6> prx:kill(Task, Pid, 0).
%% ok
%% 7> prx:kill(Task, Pid, sigkill).
%% ok
%% 8> prx:kill(Task, Pid, 0).
%% {error,esrch}
%% 9> flush().
%% Shell got {termsig,<0.158.0>,sigkill}
%% ok
%% '''
-spec kill(task(), pid_t(), constant()) -> ok | {error, posix()}.
kill(Task, OSPid, Signal) ->
    ?PRX_CALL(Task, kill, [OSPid, Signal]).

%% @doc lseek(2): set file offset for read/write
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.154.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.169.0>}
%% 3> {ok, FD} = prx:open(Task1, "/etc/passwd", [o_rdonly]).
%% {ok,7}
%% 4> prx:lseek(Task1, FD, 0, 0).
%% ok
%% '''
-spec lseek(task(), fd(), off_t(), int32_t()) -> ok | {error, posix()}.
lseek(Task, FD, Offset, Whence) ->
    ?PRX_CALL(Task, lseek, [FD, Offset, Whence]).

%% @doc mkdir(2) : create a directory
-spec mkdir(task(), iodata(), mode_t()) -> ok | {error, posix()}.
mkdir(Task, Path, Mode) ->
    ?PRX_CALL(Task, mkdir, [Path, Mode]).

%% @doc mkfifo(3) : create a named pipe
-spec mkfifo(task(), iodata(), mode_t()) -> ok | {error, posix()}.
mkfifo(Task, Path, Mode) ->
    ?PRX_CALL(Task, mkfifo, [Path, Mode]).

%% @doc mount(2) : mount a filesystem, Linux style
%%
%% The arguments are:
%%
%% • source
%%
%% • target
%%
%% • filesystem type
%%
%% • flags
%%
%% • data
%%
%% An empty list may be used to specify NULL.
%%
%% For example, filesystems mounted in a Linux mount namespace may be
%% visible in the global mount namespace. To avoid this, first remount the
%% root filesystem within mount namespace using the `MS_REC|MS_PRIVATE'
%% flags:
%%
%% ```
%% {ok, Task} = prx:clone(Parent, [clone_newns]),
%% ok = prx:mount(Task, "none", "/", "", [ms_rec, ms_private], "").
%% '''
%%
%% On BSD systems, the `Source' argument is ignored and passed to
%% the system mount call as:
%%
%%     mount(FSType, Target, Flags, Data);
%%
%% == Examples ==
%%
%% An example of bind mounting a directory within a linux mount namespace:
%%
%% ```
%% 1> prx:sudo().
%% ok
%% 2> {ok, Task} = prx:fork().
%% {ok,<0.192.0>}
%% 3> {ok, Task1} = prx:clone(Task, [clone_newns]).
%% {ok,<0.196.0>}
%% 3> prx:mount(Task1, "/tmp", "/mnt", "", [ms_bind, ms_rdonly, ms_noexec], "").
%% ok
%% 4> prx:umount(Task1, "/mnt").
%% ok
%% '''
-spec mount(task(), iodata(), iodata(), iodata(), uint64_t() | [constant()], iodata()) ->
    ok | {error, posix()}.
mount(Task, Source, Target, FSType, Flags, Data) ->
    mount(Task, Source, Target, FSType, Flags, Data, <<>>).

%% @doc (Solaris) mount(2) : mount a filesystem
%%
%% On Solaris, some mount options are passed in the `Options' argument
%% as a string of comma separated values terminated by a NULL.
%% Other platforms ignore the Options parameter.
%%
%% @see mount/6
-spec mount(task(), iodata(), iodata(), iodata(), uint64_t() | [constant()], iodata(), iodata()) ->
    ok | {error, posix()}.
mount(Task, Source, Target, FSType, Flags, Data, Options) ->
    ?PRX_CALL(Task, mount, [Source, Target, FSType, Flags, Data, Options]).

%% @doc open(2): returns a file descriptor associated with a file
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.192.0>}
%% 2> prx:open(Task, "/etc/hosts", [o_rdonly]).
%% {ok,7}
%% '''

-spec open(task(), iodata(), int32_t() | [constant()]) -> {ok, fd()} | {error, posix()}.
open(Task, Path, Flags) ->
    open(Task, Path, Flags, 0).

%% @doc open(2) : open a file specifying permissions
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.192.0>}
%% 2> prx:open(Task, "/tmp/prx-open-test", [o_wronly,o_creat], 8#644).
%% {ok,7}
%% '''
-spec open(task(), iodata(), int32_t() | [constant()], mode_t()) ->
    {ok, fd()} | {error, posix()}.
open(Task, Path, Flags, Mode) ->
    ?PRX_CALL(Task, open, [Path, Flags, Mode]).

%% @doc pivot_root(2): change the root mount
%%
%% Use pivot_root(2) in a Linux mount namespace to change the root
%% filesystem.
%%
%% Warning: using pivot_root(2) in the global namespace may have unexpected
%% effects.
%%
%% To use an arbitrary directory as a mount point:
%%
%% • mark the mount namespace as private
%%
%% • create a mount point by bind mounting the new root directory over
%%   itself
%%
%% • change the current working directory to the new root directory
%%
%% • call pivot_root(2) with new and old root set to the current working
%%   directory
%%
%% • unmount the current working directory
%%
%% == Support ==
%%
%% • Linux
%%
%% == Examples ==
%%
%% ```
%% 1> prx:sudo().
%% ok
%% 2> {ok, Task} = prx:fork().
%% {ok,<0.192.0>}
%% 3> {ok, Task1} = prx:clone(Task, [clone_newns]).
%% {ok,<0.196.0>}
%% 4> prx:mkdir(Task, "/tmp/prx-root", 8#755).
%% ok
%% 5> {ok, Task1} = prx:clone(Task, [clone_newns]).
%% {ok,<0.210.0>}
%% 6> prx:mount(Task1, "none", "/", [], [ms_rec, ms_private], []).
%% ok
%% 7> prx:mount(Task1, "/tmp/prx-root", "/tmp/prx-root", [], [ms_bind], []).
%% ok
%% 8> prx:chdir(Task1, "/tmp/prx-root").
%% ok
%% 9> prx:pivot_root(Task1, ".", ".").
%% ok
%% 10> prx:umount2(Task1, ".", [mnt_detach]).
%% ok
%% '''
-spec pivot_root(task(), iodata(), iodata()) -> ok | {error, posix()}.
pivot_root(Task, NewRoot, PutOld) ->
    ?PRX_CALL(Task, pivot_root, [NewRoot, PutOld]).

%% @doc pledge(2): restrict system operations
%%
%% An empty list ([]) specifies promises should not be changed. Warning:
%% an empty string ("") is equivalent to an empty list.
%%
%% To specify no capabilities, use an empty binary: `<<>>>' or `<<"">>'
%%
%% == Support ==
%%
%% • OpenBSD
%%
%% == Examples ==
%%
%% Fork a control process:
%%
%% • restricted to stdio, proc and exec capabilities
%%
%% • unrestricted after calling exec
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.152.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.156.0>}
%% 3> prx:pledge(Task, <<"stdio proc exec">>, []).
%% ok
%% '''
-spec pledge(task(), iodata(), iodata()) -> ok | {error, posix()}.
pledge(Task, Promises, ExecPromises) ->
    ?PRX_CALL(Task, pledge, [Promises, ExecPromises]).

%% @doc prctl(2) : operations on a process
%%
%% This function can be used to set BPF syscall filters on processes
%% (seccomp mode).
%%
%% A list can be used for prctl operations requiring a C structure
%% as an argument. List elements are used to contiguously populate
%% a buffer (it is up to the caller to add padding):
%%
%% • `binary()': the element is copied directly into the buffer
%%
%%    On return, the contents of the binary is returned to the
%%    caller.
%%
%% • `{ptr, N}': N bytes of zero'ed memory is allocated. The pointer
%%    is placed in the buffer.
%%
%%    On return, the contents of the memory is returned to the
%%    caller.
%%
%% • `{ptr, binary()}'
%%
%%    Memory equal to the size of the binary is allocated and
%%    initialized with the contents of the binary.
%%
%%    On return, the contents of the memory is returned to the
%%    caller.
%%
%% == Support ==
%%
%% • Linux
%%
%% == Examples ==
%%
%% To enforce a seccomp filter:
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
-spec prctl(task(), constant(), ptr_arg(), ptr_arg(), ptr_arg(), ptr_arg()) ->
    {ok, integer(), ptr_val(), ptr_val(), ptr_val(), ptr_val()} | {error, posix()}.
prctl(Task, Arg1, Arg2, Arg3, Arg4, Arg5) ->
    ?PRX_CALL(Task, prctl, [Arg1, Arg2, Arg3, Arg4, Arg5]).

%% @doc procctl(2): control processes
%%
%% == Support ==
%%
%% • FreeBSD
%%
%% == Examples ==
%%
%% ```
%% Pid = prx:pidof(Task),
%% prx:procctl(Task, 0, Pid, 'PROC_REAP_ACQUIRE', []),
%% prx:procctl(Task, p_pid, Pid, 'PROC_REAP_STATUS', [
%%    <<0,0,0,0>>, % rs_flags
%%    <<0,0,0,0>>, % rs_children
%%    <<0,0,0,0>>, % rs_descendants
%%    <<0,0,0,0>>, % rs_reaper
%%    <<0,0,0,0>>  % rs_pid
%% ]).
%% '''
-spec procctl(task(), constant(), pid_t(), constant(), [] | cstruct()) ->
    {ok, binary(), cstruct()} | {error, posix()}.
procctl(Task, IDType, ID, Cmd, Data) ->
    ?PRX_CALL(Task, procctl, [IDType, ID, Cmd, Data]).

%% @doc ptrace(2): process trace
%%
%% == Examples ==
%%
%% ```
%% -module(ptrace).
%%
%% -export([run/0]).
%%
%% run() ->
%%     {ok, Task} = prx:fork(),
%%     {ok, Task1} = prx:fork(Task),
%%     {ok, Task2} = prx:fork(Task1),
%%
%%     Pid2 = prx:pidof(Task2),
%%
%%     % disable the prx event loop: child process must be managed by
%%     % the caller
%%     {ok, sig_dfl} = prx:sigaction(Task1, sigchld, sig_info),
%%
%%     % enable ptracing in the child process and exec() a command
%%     {ok, 0, <<>>, <<>>} = prx:ptrace(Task2, ptrace_traceme, 0, 0, 0),
%%     ok = prx:execvp(Task2, "cat", ["cat"]),
%%
%%     % the parent is notified
%%     ok =
%%         receive
%%             {signal, Task1, sigchld, _} ->
%%                 ok
%%         after 5000 ->
%%             timeout
%%         end,
%%
%%     {ok, Pid2, _, [{stopsig, sigtrap}]} = prx:waitpid(Task1, -1, [wnohang]),
%%
%%     % should be no other events
%%     {ok, 0, 0, []} = prx:waitpid(Task1, -1, [wnohang]),
%%
%%     % allow the process to continue
%%     {ok, 0, <<>>, <<>>} = prx:ptrace(Task1, ptrace_cont, Pid2, 0, 0),
%%
%%     ok = prx:stdin(Task2, "test\n"),
%%
%%     ok =
%%         receive
%%             {stdout, Task2, <<"test\n">>} ->
%%                 ok
%%         after 5000 -> timeout
%%         end,
%%
%%     % Send a SIGTERM and re-write it to a harmless SIGWINCH
%%     ok = prx:kill(Task1, Pid2, sigterm),
%%     ok =
%%         receive
%%             {signal, Task1, sigchld, _} ->
%%                 ok
%%         after 5000 ->
%%             timeout
%%         end,
%%
%%     {ok, Pid2, _, [{stopsig, sigterm}]} = prx:waitpid(Task1, -1, [wnohang]),
%%
%%     {ok, 0, <<>>, <<>>} = prx:ptrace(Task1, ptrace_cont, Pid2, 0, 28),
%%
%%     % Convert a SIGWINCH to SIGTERM
%%     ok = prx:kill(Task1, Pid2, sigwinch),
%%     ok =
%%         receive
%%             {signal, Task1, sigchld, _} ->
%%                 ok
%%         after 5000 ->
%%             timeout
%%         end,
%%
%%     {ok, 0, <<>>, <<>>} = prx:ptrace(Task1, ptrace_cont, Pid2, 0, 15),
%%     {ok, Pid2, _, [{termsig, sigterm}]} = prx:waitpid(Task1, -1, []).
%% '''
-spec ptrace(task(), constant(), pid_t(), ptr_arg(), ptr_arg()) ->
    {ok, integer(), ptr_val(), ptr_val()} | {error, posix()}.
ptrace(Task, Request, OSPid, Addr, Data) ->
    ?PRX_CALL(Task, ptrace, [Request, OSPid, Addr, Data]).

%% @doc read(2): read bytes from a file descriptor
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.212.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.216.0>}
%% 3> {ok, FD} = prx:open(Task1, "/etc/hosts", [o_rdonly]).
%% {ok,7}
%% 4> prx:read(Task1, FD, 64).
%% {ok,<<"127.0.0.1 localhost\n\n# The following lines are desirable for IPv">>}
%% '''
-spec read(task(), fd(), size_t()) -> {ok, binary()} | {error, posix()}.
read(Task, FD, Count) ->
    ?PRX_CALL(Task, read, [FD, Count]).

%% @doc readdir(3): retrieve list of objects in a directory
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.212.0>}
%% 2> prx:readdir(Task, "/dev/pts").
%% {ok,[<<".">>,<<"..">>,<<"66">>,<<"63">>,<<"67">>,<<"64">>,
%%      <<"62">>,<<"61">>,<<"60">>,<<"59">>,<<"58">>,<<"57">>,
%%      <<"56">>,<<"55">>,<<"54">>,<<"53">>,<<"52">>,<<"51">>,
%%      <<"50">>,<<"49">>,<<"48">>,<<"47">>,<<"46">>,<<"45">>,
%%      <<"44">>,<<"43">>,<<...>>|...]}
%% '''
-spec readdir(task(), iodata()) -> {ok, [binary()]} | {error, posix()}.
readdir(Task, Path) ->
    ?PRX_CALL(Task, readdir, [Path]).

%% @doc rmdir(2): delete a directory
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.212.0>}
%% 2> prx:mkdir(Task, "/tmp/prx-rmdir-test", 8#755).
%% ok
%% 3> prx:rmdir(Task, "/tmp/prx-rmdir-test").
%% ok
%% '''
-spec rmdir(task(), iodata()) -> ok | {error, posix()}.
rmdir(Task, Path) ->
    ?PRX_CALL(Task, rmdir, [Path]).

%% @doc seccomp(2) : restrict system operations
%%
%% See prctl/6.
-spec seccomp(task(), constant(), constant(), cstruct()) -> ok | {error, posix()}.
seccomp(Task, Operation, Flags, Prog) ->
    ?PRX_CALL(Task, seccomp, [Operation, Flags, Prog]).

%% @doc setcpid() : Set options for child process of prx control process
%%
%% Control behaviour of an exec()'ed process.
%%
%% See setcpid/4 for options.
-spec setcpid(task(), atom(), int32_t()) -> boolean().
setcpid(Task, Opt, Val) when is_pid(Task) ->
    try
        ?PRX_CALL(Task, setcpid, [Opt, Val])
    catch
        exit:_ ->
            false
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
-spec setcpid(task(), task() | cpid() | pid_t(), atom(), int32_t()) -> boolean().
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
-spec setenv(task(), iodata(), iodata(), int32_t()) -> ok | {error, posix()}.
setenv(Task, Name, Value, Overwrite) ->
    ?PRX_CALL(Task, setenv, [Name, Value, Overwrite]).

%% @doc setgid(2) : set the GID of the process
-spec setgid(task(), gid_t()) -> ok | {error, posix()}.
setgid(Task, Gid) ->
    ?PRX_CALL(Task, setgid, [Gid]).

%% @doc setgroups(2) : set the supplementary groups of the process
-spec setgroups(task(), [gid_t()]) -> ok | {error, posix()}.
setgroups(Task, Groups) ->
    ?PRX_CALL(Task, setgroups, [Groups]).

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
-spec sethostname(task(), iodata()) -> ok | {error, posix()}.
sethostname(Task, Hostname) ->
    ?PRX_CALL(Task, sethostname, [Hostname]).

%% @doc (Linux) setns(2) : attach to a namespace
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
-spec setns(task(), fd()) -> ok | {error, posix()}.
setns(Task, FD) ->
    setns(Task, FD, 0).

%% @doc (Linux) setns(2) : attach to a namespace, specifying
%% namespace type
%%
%% ```
%% ok = prx:setns(Task, FD, clone_newnet)
%% '''
-spec setns(task(), fd(), constant()) -> ok | {error, posix()}.
setns(Task, FD, NSType) ->
    ?PRX_CALL(Task, setns, [FD, NSType]).

%% @doc setopt() : set options for the prx control process
%%
%% See getopt/3 for options.
-spec setopt(task(), prx_opt(), int32_t()) -> boolean().
setopt(Task, Opt, Val) ->
    ?PRX_CALL(Task, setopt, [Opt, Val]).

%% @doc setpgid(2) : set process group
-spec setpgid(task(), pid_t(), pid_t()) -> ok | {error, posix()}.
setpgid(Task, OSPid, Pgid) ->
    ?PRX_CALL(Task, setpgid, [OSPid, Pgid]).

%% @doc setpriority(2) : set scheduling priority of process, process
%% group or user
-spec setpriority(task(), constant(), int32_t(), int32_t()) -> ok | {error, posix()}.
setpriority(Task, Which, Who, Prio) ->
    ?PRX_CALL(Task, setpriority, [Which, Who, Prio]).

%% @doc setresgid(2) : set real, effective and saved group ID
%%
%% Supported on Linux and BSD's.
-spec setresgid(task(), gid_t(), gid_t(), gid_t()) -> ok | {error, posix()}.
setresgid(Task, Real, Effective, Saved) ->
    ?PRX_CALL(Task, setresgid, [Real, Effective, Saved]).

%% @doc setresuid(2) : set real, effective and saved user ID
%%
%% Supported on Linux and BSD's.
-spec setresuid(task(), uid_t(), uid_t(), uid_t()) -> ok | {error, posix()}.
setresuid(Task, Real, Effective, Saved) ->
    ?PRX_CALL(Task, setresuid, [Real, Effective, Saved]).

%% @doc setsid(2) : create a new session
-spec setsid(task()) -> {ok, pid_t()} | {error, posix()}.
setsid(Task) ->
    ?PRX_CALL(Task, setsid, []).

%% @doc setuid(2) : change UID
-spec setuid(task(), uid_t()) -> ok | {error, posix()}.
setuid(Task, User) ->
    ?PRX_CALL(Task, setuid, [User]).

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
-spec sigaction(
    task(),
    constant(),
    atom() | {sig_info, fun((pid(), [pid_t()], atom(), binary()) -> any())}
) -> {ok, atom()} | {error, posix()}.
sigaction(Task, Signal, {sig_info, Fun}) when is_atom(Signal), is_function(Fun, 4) ->
    case gen_statem:call(Task, {sigaction, Signal, Fun}, infinity) of
        ok ->
            sigaction(Task, Signal, sig_info);
        _ ->
            {error, einval}
    end;
sigaction(Task, Signal, Handler) ->
    ?PRX_CALL(Task, sigaction, [Signal, Handler]).

%% @doc socket(2) : retrieve file descriptor for communication endpoint
%%
%% ```
%% {ok, FD} = prx:socket(Task, af_inet, sock_stream, 0).
%% '''
-spec socket(task(), constant(), constant(), int32_t()) -> {ok, fd()} | {error, posix()}.
socket(Task, Domain, Type, Protocol) ->
    ?PRX_CALL(Task, socket, [Domain, Type, Protocol]).

%% @doc umount(2) : unmount a filesystem
%%
%% On BSD systems, calls unmount(2).
-spec umount(task(), iodata()) -> ok | {error, posix()}.
umount(Task, Path) ->
    ?PRX_CALL(Task, umount, [Path]).

%% @doc umount2(2) : unmount a filesystem
%%
%% On BSD systems, calls unmount(2).
-spec umount2(task(), iodata(), [constant()]) -> ok | {error, posix()}.
umount2(Task, Path, Flags) ->
    ?PRX_CALL(Task, umount2, [Path, Flags]).

%% @doc unlink(2) : delete references to a file
-spec unlink(task(), iodata()) -> ok | {error, posix()}.
unlink(Task, Path) ->
    ?PRX_CALL(Task, unlink, [Path]).

%% @doc unsetenv(3) : remove an environment variable
-spec unsetenv(task(), iodata()) -> ok | {error, posix()}.
unsetenv(Task, Name) ->
    ?PRX_CALL(Task, unsetenv, [Name]).

%% @doc (Linux) unshare(2) : allows creating a new namespace in
%% the current process
%%
%% unshare(2) lets you make a new namespace without calling clone(2):
%%
%% ```
%% % The port is now running in a namespace without network access.
%% ok = prx:unshare(Task, [clone_newnet]).
%% '''
-spec unshare(task(), int32_t() | [constant()]) -> ok | {error, posix()}.
unshare(Task, Flags) ->
    ?PRX_CALL(Task, unshare, [Flags]).

%% @doc unveil(2): restrict filesystem view
%%
%% To disable unveil calls, use an empty list ([]) or, equivalently, an
%% empty string ("").
%%
%% ```
%% prx:unveil(Task, <<"/etc">>, <<"r">>),
%% prx:unveil(Task, [], []).
%% '''
%%
%% == Support ==
%%
%% • OpenBSD
%%
%% == Examples ==
%%
%% ```
%% 1> {ok, Task} = prx:fork().
%% {ok,<0.152.0>}
%% 2> {ok, Task1} = prx:fork(Task).
%% {ok,<0.156.0>}
%% 3> prx:unveil(Task1, <<"/etc">>, <<"r">>).
%% ok
%% 4> prx:unveil(Task1, [], []).
%% ok
%% 5> prx:readdir(Task1, "/etc").
%% {ok,[<<".">>,<<"..">>,<<"acme">>,<<"amd">>,<<"authpf">>,
%%      <<"daily">>,<<"disktab">>,<<"examples">>,<<"firmware">>,
%%      <<"hotplug">>,<<"iked">>,<<"isakmpd">>,<<"ldap">>,
%%      <<"magic">>,<<"mail">>,<<"moduli">>,<<"monthly">>,
%%      <<"mtree">>,<<"netstart">>,<<"npppd">>,<<"pf.os">>,
%%      <<"ppp">>,<<"protocols">>,<<"rc">>,<<"rc.conf">>,<<"rc.d">>,
%%      <<...>>|...]}
%% 6> prx:readdir(Task1, "/tmp").
%% {error,enoent}
%% '''
-spec unveil(task(), iodata(), iodata()) -> ok | {error, posix()}.
unveil(Task, Path, Permissions) ->
    ?PRX_CALL(Task, unveil, [Path, Permissions]).

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
-spec waitpid(task(), pid_t(), int32_t() | [constant()]) ->
    {ok, pid_t(), int32_t(), [waitstatus()]} | {error, posix()}.
waitpid(Task, OSPid, Options) ->
    ?PRX_CALL(Task, waitpid, [OSPid, Options]).

%% @doc write(2): write to a file descriptor
%%
%% Writes a buffer to a file descriptor, returning the number of bytes
%% written.
-spec write(task(), fd(), iodata()) -> {ok, ssize_t()} | {error, posix()}.
write(Task, FD, Buf) ->
    ?PRX_CALL(Task, write, [FD, Buf]).
