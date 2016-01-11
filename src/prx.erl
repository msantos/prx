%%% @copyright 2015 Michael Santos <michael.santos@gmail.com>

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
-behaviour(gen_fsm).
-include_lib("alcove/include/alcove.hrl").

-export([
        fork/0, fork/1,
        clone/2,
        execvp/2,
        execve/3,
        fexecve/4,
        call/3,
        stdin/2,
        stop/1,
        start_link/1, task/4
    ]).

% Utilities
-export([
        replace_process_image/1, replace_process_image/2,
        sh/2, cmd/2
    ]).

% FSM state
-export([
        forkchain/1,
        drv/1,
        atexit/2
    ]).

% Call wrappers
-export([
        setproctitle/2,
        setrlimit/3,
        getrlimit/2,
        select/5,
        children/1,

        cap_enter/1,
        cap_fcntls_limit/3,
        cap_getmode/1,
        cap_rights_limit/3,
        chdir/2,
        chmod/3,
        chown/4,
        chroot/2,
        clearenv/1,
        close/2,
        environ/1,
        exit/2,
        fcntl/3,
        getcwd/1,
        getenv/2,
        getgid/1,
        getgroups/1,
        gethostname/1,
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
        prctl/6,
        read/3,
        readdir/2,
        rmdir/2,
        setenv/4,
        setgid/2,
        setgroups/2,
        sethostname/2,
        setns/2, setns/3,
        setpgid/3,
        setpriority/4,
        setresgid/4,
        setresuid/4,
        setsid/1,
        setuid/2,
        sigaction/3,
        umount/2,
        unlink/2,
        unsetenv/2,
        unshare/2,
        write/3
    ]).

% States
-export([
        call_state/2, call_state/3,
        exec_state/2, exec_state/3
    ]).

% Behaviours
-export([init/1, handle_event/3, handle_sync_event/4,
        handle_info/3, terminate/3, code_change/4]).

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

-type cstruct() :: nonempty_list(binary() | {ptr, binary() | non_neg_integer()}).
-type prctl_arg() :: binary() | constant() | cstruct().
-type prctl_val() :: binary() | integer() | cstruct().

-type child() :: #{pid => pid_t(), exec => boolean(), fdctl => fd(),
    stdin => fd(), stdout => fd(), stderr => fd()}.

-record(state, {
        owner,
        drv,
        forkchain,
        child = #{},
        atexit = fun(Drv, ForkChain, Pid) ->
                prx_drv:call(Drv, ForkChain, close, [maps:get(stdout, Pid)]),
                prx_drv:call(Drv, ForkChain, close, [maps:get(stdin, Pid)]),
                prx_drv:call(Drv, ForkChain, close, [maps:get(stderr, Pid)])
        end
    }).

-define(SIGREAD_FILENO, 3).
-define(SIGWRITE_FILENO, 4).
-define(FDCTL_FILENO, 5).

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
%% '''
%%
%% <ul>
%% <li>`{exec, Exec}'
%%
%%  Default: ""
%%
%%  Sets a command to run the port, such as sudo.</li>
%%
%% <li>`{progname, Path}'
%%
%%  Default: priv/prx
%%
%%  Sets the path to the prx executable.
%%
%% For example, to start the process as root:</li>
%% </ul>
%%
%% ```
%% application:set_env(prx, options, [{exec, "sudo -n"}])
%% '''
-spec fork() -> {ok, task()} | {error, file:posix()}.
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
-spec fork(task()) -> {ok, task()} | {error, file:posix()}.
fork(Task) when is_pid(Task) ->
    task(Task, self(), fork, []).

%% @doc (Linux only) clone(2) : create a new process
-spec clone(task(), [constant()]) -> {ok, task()} | {error, file:posix()}.
clone(Task, Flags) when is_pid(Task) ->
    task(Task, self(), clone, Flags).

%% @doc terminate the task
-spec stop(task()) -> ok.
stop(Task) ->
    catch gen_fsm:stop(Task),
    ok.

-spec start_link(pid()) -> {ok, task()} | {error, file:posix()}.
start_link(Owner) ->
    gen_fsm:start_link(?MODULE, [Owner, init], []).

-spec task(task(), pid(), atom(), [constant()]) -> {ok, task()} | {error, file:posix()}.
task(Task, Owner, Call, Argv) ->
    gen_fsm:sync_send_event(Task, {task, Owner, Call, Argv}, infinity).

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
    case gen_fsm:sync_send_event(Task, {Call, Argv}, infinity) of
        {prx_error, Error} ->
            erlang:error(Error, [Task, Call, Argv]);
        Reply ->
            Reply
    end.

%%
%% exec mode: replace the process image, stdio is now a stream
%%

%% @doc execvp(2) : replace the current process image using the search path
-spec execvp(task(), [iodata()]) -> ok | {error, file:posix()}.
execvp(Task, [Arg0|_] = Argv) when is_list(Argv) ->
    gen_fsm:sync_send_event(Task, {execvp, [Arg0, Argv]}, infinity).

%% @doc execve(2) : replace the process image, specifying the environment
%% for the new process image.
-spec execve(task(), [iodata()], [iodata()]) -> ok | {error, file:posix()}.
execve(Task, [Arg0|_] = Argv, Env) when is_list(Argv), is_list(Env) ->
    gen_fsm:sync_send_event(Task, {execve, [Arg0, Argv, Env]}, infinity).

%% @doc fexecve(2) : replace the process image, specifying the environment
%% for the new process image, using a previously opened file descriptor. The
%% file descriptor can be set to close after exec() by passing the O_CLOEXEC
%% flag to open:
%% ```
%% {ok, FD} = prx:open(Task, "/bin/ls", [o_rdonly,o_cloexec]),
%% ok = prx:fexecve(Task, FD, ["-al"], ["FOO=123"]).
%% '''
-spec fexecve(task(), int32_t(), [iodata()], [iodata()]) -> ok | {error, file:posix()}.
fexecve(Task, FD, Argv, Env) when is_integer(FD), is_list(Argv), is_list(Env) ->
    gen_fsm:sync_send_event(Task, {fexecve, [FD, [""|Argv], Env]}, infinity).

% @doc Replace the port process image using exec()
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
-spec replace_process_image(task()) -> ok | {error, eacces}.
replace_process_image(Task) ->
    replace_process_image(Task,
        alcove_drv:getopts([
                {progname, prx_drv:progname()},
                {depth, length(forkchain(Task))}
            ])).
-spec replace_process_image(task(), [iodata()]) -> ok | {error, eacces}.
replace_process_image(Task, [Arg0|_] = Argv) when is_list(Argv) ->
    % Temporarily remove the close-on-exec flag: since these fd's are
    % part of the operation of the port, any errors are fatal and should
    % kill the OS process.
    try [ {ok, _} = cloexec(Task, FD, unset) || FD <- [
            ?SIGREAD_FILENO,
            ?SIGWRITE_FILENO,
            ?FDCTL_FILENO
        ] ]
    catch
        _:Error1 ->
            prx:stop(Task),
            erlang:error(Error1)
    end,

    Reply = gen_fsm:sync_send_event(Task, {
            replace_process_image,
            [Arg0, Argv]
        }, infinity),

    try [ {ok, _} = cloexec(Task, FD, set) || FD <- [
            ?SIGREAD_FILENO,
            ?SIGWRITE_FILENO,
            ?FDCTL_FILENO
        ] ]
    catch
        _:Error2 ->
            prx:stop(Task),
            erlang:error(Error2)
    end,

    Reply.

%% @doc Send data to the standard input of the process.
-spec stdin(task(), iodata()) -> ok.
stdin(Task, Buf) ->
    stdin_chunk(Task, iolist_to_binary(Buf)).

stdin_chunk(Task, <<Buf:32768/bytes, Rest/binary>>) ->
    gen_fsm:send_event(Task, {stdin, Buf}),
    stdin_chunk(Task, Rest);
stdin_chunk(Task, Buf) ->
    gen_fsm:send_event(Task, {stdin, Buf}).

%%
%% Utilities
%%
-spec cmd(task(), [iodata()]) -> binary() | {error, file:posix()}.
cmd(Task, Cmd) ->
    system(Task, Cmd).

-spec sh(task(), iodata()) -> binary() | {error, file:posix()}.
sh(Task, Cmd) ->
    cmd(Task, ["/bin/sh", "-c", Cmd]).


%%
%% Retrieve internal state
%%

-spec forkchain(task()) -> [pid_t()].
forkchain(Task) ->
    gen_fsm:sync_send_event(Task, forkchain, infinity).

-spec drv(task()) -> pid().
drv(Task) ->
    gen_fsm:sync_send_event(Task, drv, infinity).

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
    gen_fsm:sync_send_event(Task, {atexit, Fun}, infinity).

%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================

%% @private
init([Owner, init]) ->
    process_flag(trap_exit, true),
    case prx_drv:start_link() of
        {ok, Drv} ->
            gen_server:call(Drv, init, infinity),
            {ok, call_state, #state{drv = Drv, forkchain = [], owner = Owner}};
        Error ->
            {stop, Error}
    end;
init([Drv, Owner, Chain, Call, Argv]) when Call == fork; Call == clone ->
    process_flag(trap_exit, true),
    case prx_drv:call(Drv, Chain, Call, Argv) of
        {ok, ForkChain} ->
            {ok, call_state, #state{drv = Drv, forkchain = ForkChain, owner = Owner}};
        {error, Error} ->
            {stop, Error}
    end.

%% @private
handle_event(_Event, StateName, State) ->
    {next_state, StateName, State}.

%% @private
handle_sync_event(_Event, _From, StateName, State) ->
    {next_state, StateName, State}.

%% @private
handle_info({alcove_event, Drv, ForkChain, {exit_status, Status}}, _StateName, #state{
        drv = Drv,
        forkchain = ForkChain,
        owner = Owner
    } = State) ->
    Owner ! {exit_status, self(), Status},
    {stop, shutdown, State};
handle_info({alcove_event, Drv, ForkChain, {termsig,Sig}}, _StateName, #state{
        drv = Drv,
        forkchain = ForkChain,
        owner = Owner
    } = State) ->
    Owner ! {termsig, self(), Sig},
    {stop, shutdown, State};

handle_info({alcove_stdout, Drv, ForkChain, Buf}, exec_state, #state{
        drv = Drv,
        forkchain = ForkChain,
        owner = Owner
    } = State) ->
    Owner ! {stdout, self(), Buf},
    {next_state, exec_state, State};
handle_info({alcove_stderr, Drv, ForkChain, Buf}, exec_state, #state{
        drv = Drv,
        forkchain = ForkChain,
        owner = Owner
    } = State) ->
    Owner ! {stderr, self(), Buf},
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

handle_info({alcove_event, Drv, ForkChain, {signal, Signal}}, call_state, #state{
        drv = Drv,
        forkchain = ForkChain,
        owner = Owner
    } = State) ->
    Owner ! {signal, self(), Signal},
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
        child = Child,
        atexit = Atexit
    } = State) ->
    case maps:find(Task, Child) of
        error ->
            ok;
        {ok, Pid} ->
            [ Atexit(Drv, ForkChain, child_to_map(X))
                    || X <- prx_drv:call(Drv, ForkChain, pid, []), X#alcove_pid.pid =:= Pid ]
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

%% @private
% Stdin sent while the process is in call state is discarded.
call_state(_, State) ->
    {next_state, call_state, State}.

%% @private
call_state({task, Owner, Call, Argv}, _From, #state{drv = Drv, forkchain = ForkChain, child = Child} = State) ->
    case gen_fsm:start_link(?MODULE, [Drv, Owner, ForkChain, Call, Argv], []) of
        {ok, Task} ->
            [Pid|_] = lists:reverse(prx:forkchain(Task)),
            {reply, {ok, Task}, call_state, State#state{child = maps:put(Task, Pid, Child)}};
        Error ->
            {reply, Error, call_state, State}
    end;

call_state({Call, Argv}, {Owner, _Tag}, #state{
        drv = Drv,
        forkchain = ForkChain,
        owner = Owner
    } = State) when Call =:= execvp; Call =:= execve; Call =:= fexecve ->
    case prx_drv:call(Drv, ForkChain, pid, []) of
        [] ->
            case prx_drv:call(Drv, ForkChain, Call, Argv) of
                ok ->
                    {reply, ok, exec_state, State};
                Error ->
                    {reply, Error, call_state, State}
            end;
        [#alcove_pid{}|_] ->
            {reply, {error,eacces}, call_state, State}
    end;

call_state({replace_process_image, Argv}, {Owner, _Tag}, #state{
        drv = Drv,
        forkchain = ForkChain,
        owner = Owner
    } = State) ->
    case prx_drv:call(Drv, ForkChain, pid, []) of
        [] ->
            Reply = prx_drv:call(Drv, ForkChain, execvp, Argv),
            {reply, Reply, call_state, State};
        [#alcove_pid{}|_] ->
            {reply, {error,eacces}, call_state, State}
    end;

call_state(drv, {Owner, _Tag}, #state{
        drv = Drv,
        owner = Owner
    } = State) ->
    {reply, Drv, call_state, State};

call_state(forkchain, {_Owner, _Tag}, #state{
        forkchain = ForkChain
    } = State) ->
    {reply, ForkChain, call_state, State};

call_state({atexit, Fun}, {Owner, _Tag}, #state{
        owner = Owner
    } = State) ->
    {reply, ok, call_state, State#state{atexit = Fun}};

call_state({Call, Argv}, {Owner, _Tag}, #state{
        drv = Drv,
        forkchain = ForkChain,
        owner = Owner
    } = State) ->
    Reply = prx_drv:call(Drv, ForkChain, Call, Argv),
    {reply, Reply, call_state, State};

call_state(_, _From, State) ->
    {reply, {error,einval}, call_state, State}.

%% @private
exec_state({stdin, Buf}, #state{drv = Drv, forkchain = ForkChain} = State) ->
    prx_drv:stdin(Drv, ForkChain, Buf),
    {next_state, exec_state, State};

exec_state(_, State) ->
    {next_state, exec_state, State}.

%% @private
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
exec_state(forkchain, {_Owner, _Tag}, #state{
        forkchain = ForkChain
    } = State) ->
    {reply, ForkChain, exec_state, State};

exec_state(_, _From, State) ->
    {reply, {prx_error,einval}, exec_state, State}.


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
            system_exec(Child, Cmd);
        Error ->
            Error
    end,

    % Child has returned, restore the parent's signal handlers
    {ok, _} = sigaction(Task, sigint, Int),
    {ok, _} = sigaction(Task, sigquit, Quit),
    Stdout.

system_exec(Task, Cmd) ->
    case prx:execvp(Task, Cmd) of
        ok ->
            receive
                {exit_status, Task, _} ->
                    flush_stdio(Task);
                {termsig, Task, _} ->
                    flush_stdio(Task)
            end;
        Error ->
            stop(Task),
            Error
    end.

flush_stdio(Task) ->
    flush_stdio(Task, []).
flush_stdio(Task, Acc) ->
    receive
        {stdout, Task, Buf} ->
            flush_stdio(Task, [Buf|Acc]);
        {stderr, Task, Buf} ->
            flush_stdio(Task, [Buf|Acc])
    after
        0 ->
            list_to_binary(lists:reverse(Acc))
    end.

maybe_binary(N) when is_list(N) ->
    iolist_to_binary(N);
maybe_binary(N) when is_binary(N) ->
    N.

cloexec(Task, FD, Status) ->
    FD_CLOEXEC = call(Task, fcntl_constant, [fd_cloexec]),
    {ok, Flags0} = fcntl(Task, FD, f_getfd),
    Flags1 = case Status of
        set -> Flags0 bor FD_CLOEXEC;
        unset -> Flags0 band (bnot FD_CLOEXEC)
    end,
    fcntl(Task, FD, f_setfd, Flags1).

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
%% Uses prctl(2) on Linux.
-spec setproctitle(task(), iodata()) -> ok.
setproctitle(Task, Name) ->
    case os:type() of
        {unix,linux} ->
            call(Task, prctl, [pr_set_name, maybe_binary(Name), 0,0,0]),
            ok;
        {unix,sunos} ->
            ok;
        {unix, BSD} when BSD =:= freebsd; BSD =:= openbsd; BSD =:= netbsd; BSD =:= darwin ->
            call(Task, setproctitle, [Name]);
        _ ->
            ok
    end.

%%
%% Convert records to maps
%%

%% @doc Returns the list of child PIDs for this process.
%%
%% Each child task is a map composed of:
%% <ul>
%%  <li>pid: system pid</li>
%%  <li>exec: true if the child has called exec()</li>
%%  <li>fdctl: parent end of CLOEXEC file descriptor used to monitor if
%%      the child process has called exec()</li>
%%  <li>stdin: parent end of the child process' standard input</li>
%%  <li>stdout: parent end of the child process' standard output</li>
%%  <li>stderr: parent end of the child process' standard error</li>
%% </ul>
-spec children(task()) -> [child()].
children(Task) ->
    [ child_to_map(Pid) || Pid <- call(Task, pid, []) ].

child_to_map(#alcove_pid{
        pid = Pid,
        fdctl = Ctl,
        stdin = In,
        stdout = Out,
        stderr = Err
    }) ->
    #{pid => Pid, exec => Ctl =:= -2, fdctl => Ctl,
        stdin => In, stdout => Out, stderr => Err}.

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
-spec getrlimit(task(), constant()) -> {ok, #{cur => uint64_t(), max => uint64_t()}} | {error, file:posix()}.
getrlimit(Task, Resource) ->
    case call(Task, getrlimit, [Resource]) of
        {ok, #alcove_rlimit{cur = Cur, max = Max}} ->
            {ok, #{cur => Cur, max => Max}};
        Error ->
            Error
    end.

%% @doc setrlimit(2) : set a resource limit
-spec setrlimit(task(), constant(), #{cur => uint64_t(), max => uint64_t()}) -> ok | {error, file:posix()}.
setrlimit(Task, Resource, Rlim) ->
    #{cur := Cur, max := Max} = Rlim,
    call(Task, setrlimit, [Resource, #alcove_rlimit{cur = Cur, max = Max}]).

%% @doc select(2) : poll a list of file descriptor for events
%%
%% select/6 will block until an event occurs on a file descriptor,
%% a timeout is reached or interrupted by a signal.
%%
%% The Timeout value may be:
%%
%% <ul>
%% <li> an empty binary (`<<>>') signifying no value (block forever)</li>
%%
%% <li> a map with these fields:</li>
%%
%%     <ul>
%%     <li>sec : number of seconds to wait</li>
%%     <li>usec : number of microseconds to wait</li>
%%     </ul>
%%
%% </ul>
-spec select(task(), [fd()], [fd()], [fd()], <<>> | #{sec => int64_t(), usec => int64_t()}) -> {ok, [fd()], [fd()], [fd()]} | {error,file:posix()}.
select(Task, Readfds, Writefds, Exceptfds, Timeout) when is_map(Timeout) ->
    Sec = maps:get(sec, Timeout, 0),
    Usec = maps:get(usec, Timeout, 0),
    call(Task, select, [Readfds, Writefds, Exceptfds, #alcove_timeval{sec = Sec, usec = Usec}]);
select(Task, Readfds, Writefds, Exceptfds, <<>>) ->
    call(Task, select, [Readfds, Writefds, Exceptfds, <<>>]).


%%
%% Convenience wrappers with types defined
%%

%% @doc (FreeBSD only) cap_enter(2) : put process into capability mode
-spec cap_enter(task()) -> 'ok' | {'error', file:posix()}.
cap_enter(Task) ->
    call(Task, cap_enter, []).

%% @doc (FreeBSD only) cap_fcntls_limit(2) : set allowed fnctl(2)
%% commands on file descriptor
-spec cap_fcntls_limit(task(), fd(), [constant()])
    -> 'ok' | {'error', file:posix()}.
cap_fcntls_limit(Task, Arg1, Arg2) ->
    call(Task, cap_fcntls_limit, [Arg1, Arg2]).

%% @doc (FreeBSD only) cap_getmode(2) : returns capability mode status
%% of process:
%% ```
%%  0 : false
%%  1 : true
%% '''
-spec cap_getmode(task()) -> {'ok', 0 | 1} | {'error', file:posix()}.
cap_getmode(Task) ->
    call(Task, cap_getmode, []).

%% @doc (FreeBSD only) cap_rights_limit(2) : set allowed rights(4)
%% of file descriptor
-spec cap_rights_limit(task(), fd(), [constant()])
    -> 'ok' | {'error', file:posix()}.
cap_rights_limit(Task, Arg1, Arg2) ->
    call(Task, cap_rights_limit, [Arg1, Arg2]).

%% @doc chdir(2) : change process current working directory.
-spec chdir(task(),iodata()) -> 'ok' | {'error', file:posix()}.
chdir(Task, Arg1) ->
    call(Task, chdir, [Arg1]).

%% @doc chmod(2) : change file permissions
-spec chmod(task(),iodata(),mode_t()) -> 'ok' | {'error', file:posix()}.
chmod(Task, Arg1, Arg2) ->
    call(Task, chmod, [Arg1, Arg2]).

%% @doc chown(2) : change file ownership
-spec chown(task(),iodata(),uid_t(),gid_t()) -> 'ok' | {'error', file:posix()}.
chown(Task, Arg1, Arg2, Arg3) ->
    call(Task, chown, [Arg1, Arg2, Arg3]).

%% @doc chroot(2) : change root directory
-spec chroot(task(),iodata()) -> 'ok' | {'error', file:posix()}.
chroot(Task, Arg1) ->
    call(Task, chroot, [Arg1]).

%% @doc clearenv(3) : zero process environment
-spec clearenv(task()) -> 'ok' | {'error', file:posix()}.
clearenv(Task) ->
    call(Task, clearenv, []).

%% @doc close(2) : close a file descriptor.
-spec close(task(),fd()) -> 'ok' | {'error', file:posix()}.
close(Task, Arg1) ->
    call(Task, close, [Arg1]).

%% @doc environ(7) : return the process environment variables
-spec environ(task()) -> [binary()].
environ(Task) ->
    call(Task, environ, []).

%% @doc exit(3) : cause the child process to exit
-spec exit(task(),int32_t()) -> 'ok'.
exit(Task, Arg1) ->
    call(Task, exit, [Arg1]).

%% @doc fcntl(2) : perform operations on a file descriptor
-spec fcntl(task(), fd(), constant()) -> {'ok',int64_t()} | {'error', file:posix()}.
fcntl(Task, Arg1, Arg2) ->
    call(Task, fcntl, [Arg1, Arg2, 0]).

-spec fcntl(task(), fd(), constant(), int64_t()) -> {'ok',int64_t()} | {'error', file:posix()}.
fcntl(Task, Arg1, Arg2, Arg3) ->
    call(Task, fcntl, [Arg1, Arg2, Arg3]).

%% @doc getcwd(3) : return the current working directory
-spec getcwd(task()) -> {'ok', binary()} | {'error', file:posix()}.
getcwd(Task) ->
    call(Task, getcwd, []).

%% @doc getenv(3) : retrieve an environment variable
-spec getenv(task(),iodata()) -> binary() | 'false'.
getenv(Task, Arg1) ->
    call(Task, getenv, [Arg1]).

%% @doc getgid(2) : retrieve the processes' group ID
-spec getgid(task()) -> gid_t().
getgid(Task) ->
    call(Task, getgid, []).

%% @doc getgroups(2) : retrieve the list of supplementary groups
-spec getgroups(task()) -> {'ok', [gid_t()]} | {'error', file:posix()}.
getgroups(Task) ->
    call(Task, getgroups, []).

%% @doc gethostname(2) : retrieve the system hostname
-spec gethostname(task()) -> {'ok', binary()} | {'error', file:posix()}.
gethostname(Task) ->
    call(Task, gethostname, []).

%% @doc getpgrp(2) : retrieve the process group.
-spec getpgrp(task()) -> pid_t().
getpgrp(Task) ->
    call(Task, getpgrp, []).

%% @doc getpid(2) : retrieve the system PID of the process.
-spec getpid(task()) -> pid_t().
getpid(Task) ->
    call(Task, getpid, []).

%% @doc getpriority(2) : retrieve scheduling priority of process,
%% process group or user
-spec getpriority(task(),constant(),int32_t()) -> {'ok',int32_t()} | {'error', file:posix()}.
getpriority(Task, Arg1, Arg2) ->
    call(Task, getpriority, [Arg1, Arg2]).

%% @doc getresgid(2) : get real, effective and saved group ID
%%
%% Supported on Linux and BSD's.
-spec getresgid(task()) -> {'ok', gid_t(), gid_t(), gid_t()} | {'error', file:posix()}.
getresgid(Task) ->
    call(Task, getresgid, []).

%% @doc getresuid(2) : get real, effective and saved user ID
%%
%% Supported on Linux and BSD's.
-spec getresuid(task()) -> {'ok', uid_t(), uid_t(), uid_t()} | {'error', file:posix()}.
getresuid(Task) ->
    call(Task, getresuid, []).

%% @doc getsid(2) : retrieve the session ID
-spec getsid(task(),pid_t()) -> {'ok', pid_t()} | {'error', file:posix()}.
getsid(Task, Arg1) ->
    call(Task, getsid, [Arg1]).

%% @doc getuid(2) : returns the process user ID
-spec getuid(task()) -> uid_t().
getuid(Task) ->
    call(Task, getuid, []).

%% @doc ioctl(2) : control device
%%
%% Controls a device using a file descriptor previously obtained
%% using open/5.
%%
%% Argp can be either a binary or a list represention of a C
%% struct. See prctl/7 below for a description of the list elements.
%%
%% An example of creating a tap device in a net namespace on Linux:
%%
%% ```
%% {ok, Child} = prx:clone(Task, [clone_newnet]),
%% {ok, FD} = prx:open(Child, "/dev/net/tun", [o_rdwr], 0),
%% {ok, <<"tap", N, _/binary>>} = prx:ioctl(Child, FD,
%%     tunsetiff, <<
%%     0:(16*8), % generate a tuntap device name
%%     (16#0002 bor 16#1000):2/native-unsigned-integer-unit:8, % IFF_TAP, IFF_NO_PI
%%     0:(14*8)
%%     >>),
%% {ok, <<"tap", N>>}.
%% '''
-spec ioctl(task(), fd(), constant(), cstruct()) -> {'ok',iodata()} | {'error', file:posix()}.
ioctl(Task, Arg1, Arg2, Arg3) ->
    call(Task, ioctl, [Arg1, Arg2, Arg3]).

%% @doc (FreeBSD only) jail(2) : restrict the current process in a system jail
-spec jail(task(),
    #{version => alcove:uint32_t(),
      path => iodata(),
      hostname => iodata(),
      jailname => iodata(),
      ip4 => [inet:ip4_address()],
      ip6 => [inet:ip6_address()]} | cstruct())
    -> {'ok', int32_t()} | {'error', file:posix()}.
jail(Task, Arg1) when is_map(Arg1) ->
    jail(Task, alcove_cstruct:jail(map_to_jail(Arg1)));
jail(Task, Arg1) ->
    call(Task, jail, [Arg1]).

%% @doc kill(2) : terminate a process
-spec kill(task(),pid_t(),constant()) -> 'ok' | {'error', file:posix()}.
kill(Task, Arg1, Arg2) ->
    call(Task, kill, [Arg1, Arg2]).

%% @doc lseek(2) : set file offset for read/write
-spec lseek(task(),fd(),off_t(),int32_t()) -> 'ok' | {'error', file:posix()}.
lseek(Task, Arg1, Arg2, Arg3) ->
    call(Task, lseek, [Arg1, Arg2, Arg3]).

%% @doc mkdir(2) : create a directory
-spec mkdir(task(),iodata(),mode_t()) -> 'ok' | {'error', file:posix()}.
mkdir(Task, Arg1, Arg2) ->
    call(Task, mkdir, [Arg1, Arg2]).

%% @doc mkfifo(3) : create a named pipe
-spec mkfifo(task(),iodata(),mode_t()) -> 'ok' | {'error', file:posix()}.
mkfifo(Task, Arg1, Arg2) ->
    call(Task, mkfifo, [Arg1, Arg2]).

%% @doc mount(2) : mount a filesystem, Linux style
%%
%% On BSD systems, the Source argument is ignored and passed to
%% the system mount call as:
%%
%%     mount(FSType, Target, Flags, Data);
%%
%% On Solaris, some mount options are passed in the Options argument
%% as a string of comma separated values terminated by a NULL.
%% Other platforms ignore the Options parameter.
-spec mount(task(),iodata(),iodata(),iodata(),uint64_t() | [constant()],iodata()) -> 'ok' | {'error', file:posix()}.
mount(Task, Arg1, Arg2, Arg3, Arg4, Arg5) ->
    mount(Task, Arg1, Arg2, Arg3, Arg4, Arg5, <<>>).
-spec mount(task(),iodata(),iodata(),iodata(),uint64_t() | [constant()],iodata(),iodata()) -> 'ok' | {'error', file:posix()}.
mount(Task, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6) ->
    call(Task, mount, [Arg1, Arg2, Arg3, Arg4, Arg5, Arg6]).

%% @doc open(2) : returns a file descriptor associated with a file
%%
%% Lists of values are OR'ed:
%%
%% ```
%% prx:open(Task, "/tmp/test", [o_wronly,o_creat], 8#644)
%% '''
-spec open(task(),iodata(),int32_t() | [constant()]) -> {'ok',fd()} | {'error', file:posix()}.
open(Task, Arg1, Arg2) ->
    open(Task, Arg1, Arg2, 0).
-spec open(task(),iodata(),int32_t() | [constant()],mode_t()) -> {'ok',fd()} | {'error', file:posix()}.
open(Task, Arg1, Arg2, Arg3) ->
    call(Task, open, [Arg1, Arg2, Arg3]).

%% @doc pivot_root(2) : change the root filesystem
-spec pivot_root(task(),iodata(),iodata()) -> 'ok' | {'error', file:posix()}.
pivot_root(Task, Arg1, Arg2) ->
    call(Task, pivot_root, [Arg1, Arg2]).

%% @doc (Linux only) prctl(2) : operations on a process
%%
%% This function can be used to set BPF syscall filters on processes
%% (seccomp mode).
%%
%% A list can be used for prctl operations requiring a C structure
%% as an argument. List elements are used to contiguously populate
%% a buffer (it is up to the caller to add padding):
%%
%% <ul>
%% <li>binary(): the element is copied directly into the buffer
%%
%%               On return, the contents of the binary is returned
%%               to the caller.</li>
%%
%% <li>{ptr, N}: N bytes of memory is allocated and zero'ed. The
%%               pointer is placed in the buffer.
%%
%%               On return, the contents of the memory is returned
%%               to the caller.</li>
%%
%% <li>{ptr, binary()}:
%%
%%               Memory equal to the size of the binary is
%%               allocated and initialized with the contents of
%%               the binary.
%%
%%               On return, the contents of the memory is returned
%%               to the caller.</li>
%% </ul>
%%
%% For example, to enforce a seccomp filter:
%%
%% ```
%% % NOTE: this filter will cause the port to receive a SIGSYS
%% % See test/alcove_seccomp_tests.erl for all the syscalls
%% % required for the port process to run
%%
%% Arch = alcove:define(Drv, [], alcove:audit_arch()),
%% Filter = [
%%     ?VALIDATE_ARCHITECTURE(Arch),
%%     ?EXAMINE_SYSCALL,
%%     sys_read,
%%     sys_write
%% ],
%%
%% {ok,_,_,_,_,_} = alcove:prctl(Drv, [], pr_set_no_new_privs, 1, 0, 0, 0),
%% Pad = (erlang:system_info({wordsize,external}) - 2) * 8,
%%
%% Prog = [
%%     <<(iolist_size(Filter) div 8):2/native-unsigned-integer-unit:8>>,
%%     <<0:Pad>>,
%%     {ptr, list_to_binary(Filter)}
%% ],
%% alcove:prctl(Drv, [], pr_set_seccomp, seccomp_mode_filter, Prog, 0, 0).
%% '''
-spec prctl(task(),constant(),prctl_arg(),prctl_arg(),prctl_arg(),prctl_arg())
    -> {'ok',integer(),prctl_val(),prctl_val(),prctl_val(),prctl_val()} | {'error', file:posix()}.
prctl(Task, Arg1, Arg2, Arg3, Arg4, Arg5) ->
    call(Task, prctl, [Arg1, Arg2, Arg3, Arg4, Arg5]).

%% @doc read(2) : read bytes from a file descriptor
-spec read(task(),fd(),size_t()) -> {'ok', binary()} | {'error', file:posix()}.
read(Task, Arg1, Arg2) ->
    call(Task, read, [Arg1, Arg2]).

%% @doc readdir(3) : retrieve list of objects in a directory
-spec readdir(task(),iodata()) -> {'ok', [binary()]} | {'error', file:posix()}.
readdir(Task, Arg1) ->
    call(Task, readdir, [Arg1]).

%% @doc rmdir(2) : delete a directory
-spec rmdir(task(),iodata()) -> 'ok' | {'error', file:posix()}.
rmdir(Task, Arg1) ->
    call(Task, rmdir, [Arg1]).

%% @doc setenv(3) : set an environment variable
-spec setenv(task(),iodata(),iodata(),int32_t()) -> 'ok' | {'error', file:posix()}.
setenv(Task, Arg1, Arg2, Arg3) ->
    call(Task, setenv, [Arg1, Arg2, Arg3]).

%% @doc setgid(2) : set the GID of the process
-spec setgid(task(),gid_t()) -> 'ok' | {'error', file:posix()}.
setgid(Task, Arg1) ->
    call(Task, setgid, [Arg1]).

%% @doc setgroups(2) : set the supplementary groups of the process
-spec setgroups(task(), [gid_t()]) -> 'ok' | {'error', file:posix()}.
setgroups(Task, Arg1) ->
    call(Task, setgroups, [Arg1]).

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
-spec sethostname(task(),iodata()) -> 'ok' | {'error', file:posix()}.
sethostname(Task, Arg1) ->
    call(Task, sethostname, [Arg1]).

%% @doc (Linux only) setns(2) : attach to a namespace
%%
%% A process namespace is represented as a path in the /proc
%% filesystem. The path is `/proc/<pid>/ns/<ns>', where:
%%
%%  pid = the system PID
%%  ns = a file representing the namespace
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
-spec setns(task(),iodata()) -> 'ok' | {'error', file:posix()}.
setns(Task, Arg1) ->
    setns(Task, Arg1, 0).
-spec setns(task(),iodata(),constant()) -> 'ok' | {'error', file:posix()}.
setns(Task, Arg1, Arg2) ->
    call(Task, setns, [Arg1, Arg2]).

%% @doc setpgid(2) : set process group
-spec setpgid(task(),pid_t(),pid_t()) -> 'ok' | {'error', file:posix()}.
setpgid(Task, Arg1, Arg2) ->
    call(Task, setpgid, [Arg1, Arg2]).

%% @doc setpriority(2) : set scheduling priority of process, process
%%      group or user
-spec setpriority(task(),constant(),int32_t(),int32_t()) -> 'ok' | {'error', file:posix()}.
setpriority(Task, Arg1, Arg2, Arg3) ->
    call(Task, setpriority, [Arg1, Arg2, Arg3]).

%% @doc setresgid(2) : set real, effective and saved group ID
%%
%%      Supported on Linux and BSD's.
-spec setresgid(task(),gid_t(),gid_t(),gid_t()) -> 'ok' | {'error', file:posix()}.
setresgid(Task, Arg1, Arg2, Arg3) ->
    call(Task, setresgid, [Arg1, Arg2, Arg3]).

%% @doc setresuid(2) : set real, effective and saved user ID
%%
%%      Supported on Linux and BSD's.
-spec setresuid(task(),uid_t(),uid_t(),uid_t()) -> 'ok' | {'error', file:posix()}.
setresuid(Task, Arg1, Arg2, Arg3) ->
    call(Task, setresuid, [Arg1, Arg2, Arg3]).

%% @doc setsid(2) : create a new session
-spec setsid(task()) -> {ok,pid_t()} | {error, file:posix()}.
setsid(Task) ->
    call(Task, setsid, []).

%% @doc setuid(2) : change UID
-spec setuid(task(),uid_t()) -> 'ok' | {'error', file:posix()}.
setuid(Task, Arg1) ->
    call(Task, setuid, [Arg1]).

%% @doc sigaction(2) : set process behaviour for signals
%%
%% <ul>
%% <li>sig_dfl : uses the default behaviour for the signal</li>
%%
%% <li>sig_ign : ignores the signal</li>
%%
%% <li>sig_catch : catches the signal and sends the controlling Erlang
%%                 process an event, {signal, atom()}</li>
%%
%% </ul>
%%
%% Multiple caught signals of the same type may be reported as one event.
-spec sigaction(task(),constant(),atom()) -> {'ok',atom()} | {'error', file:posix()}.
sigaction(Task, Arg1, Arg2) ->
    call(Task, sigaction, [Arg1, Arg2]).

%% @doc umount(2) : unmount a filesystem
%%
%%      On BSD systems, calls unmount(2).
-spec umount(task(),iodata()) -> 'ok' | {error, file:posix()}.
umount(Task, Arg1) ->
    call(Task, umount, [Arg1]).

%% @doc unlink(2) : delete references to a file
-spec unlink(task(),iodata()) -> 'ok' | {error, file:posix()}.
unlink(Task, Arg1) ->
    call(Task, unlink, [Arg1]).

%% @doc unsetenv(3) : remove an environment variable
-spec unsetenv(task(),iodata()) -> 'ok' | {error, file:posix()}.
unsetenv(Task, Arg1) ->
    call(Task, unsetenv, [Arg1]).

%% @doc (Linux only) unshare(2) : allows creating a new namespace in
%% the current process
%%
%% unshare(2) lets you make a new namespace without calling clone(2):
%%
%% ```
%% % The port is now running in a namespace without network access.
%% ok = prx:unshare(Task, [clone_newnet]).
%% '''
-spec unshare(task(),int32_t() | [constant()]) -> 'ok' | {'error', file:posix()}.
unshare(Task, Arg1) ->
    call(Task, unshare, [Arg1]).

%% @doc write(2): writes a buffer to a file descriptor and returns the
%%      number of bytes written.
-spec write(task(),fd(),iodata()) -> {'ok', ssize_t()} | {'error', file:posix()}.
write(Task, Arg1, Arg2) ->
    call(Task, write, [Arg1, Arg2]).
