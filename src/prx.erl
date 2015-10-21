%%% Copyright (c) 2015, Michael Santos <michael.santos@gmail.com>
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
        call/3,
        stdin/2,
        stop/1,
        start_link/1, task/4
    ]).

% Utilities
-export([
        replace_process_image/1, replace_process_image/2,
        sh/2, cmd/2,
        sandbox/1, sandbox/2,
        id/0,
        name/1
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

        chdir/2,
        chmod/3,
        chown/4,
        chroot/2,
        clearenv/1,
        close/2,
        environ/1,
        exit/2,
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

-type cstruct() :: [binary() | {ptr, binary() | non_neg_integer()} ] | binary() | integer() | atom().
-type prctl_val() :: binary() | integer().

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
-spec fork() -> {ok, task()} | {error, file:posix()}.
fork() ->
    start_link(self()).

-spec fork(task()) -> {ok, task()} | {error, file:posix()}.
fork(Task) when is_pid(Task) ->
    task(Task, self(), fork, []).

-spec clone(task(), [constant()]) -> {ok, task()} | {error, file:posix()}.
clone(Task, Flags) when is_pid(Task) ->
    task(Task, self(), clone, Flags).

-spec stop(task()) -> ok.
stop(Task) ->
    catch gen_fsm:stop(Task),
    ok.

-spec start_link(pid()) -> {ok, task()} | {error, file:posix()}.
start_link(Owner) ->
    case gen_fsm:start_link(?MODULE, [Owner, init], []) of
        {ok, Task} = Reply ->
            [Pid] = io_lib:format("~w", [Task]),
            setproctitle(Task, list_to_binary(["prxctl-", Pid])),
            Reply;
        Error ->
            Error
    end.

-spec task(task(), pid(), atom(), [constant()]) -> {ok, task()} | {error, file:posix()}.
task(Task, Owner, Call, Argv) ->
    case gen_fsm:sync_send_event(Task, {task, Owner, Call, Argv}, infinity) of
        {ok, Child} = Reply ->
            [Pid] = io_lib:format("~w", [Child]),
            setproctitle(Child, list_to_binary(["prx-", Pid])),
            Reply;
        Error ->
            Error
    end.

%%
%% call mode: request the task perform operations
%%
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
-spec execvp(task(), [iodata()]) -> ok | {error, file:posix()}.
execvp(Task, [Arg0|_] = Argv) when is_list(Argv) ->
    gen_fsm:sync_send_event(Task, {execvp, [Arg0, Argv]}, infinity).

-spec execve(task(), [iodata()], [iodata()]) -> ok | {error, file:posix()}.
execve(Task, [Arg0|_] = Argv, Env) when is_list(Argv), is_list(Env) ->
    gen_fsm:sync_send_event(Task, {execve, [Arg0, Argv, Env]}, infinity).

% Replace the port process image using exec()
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
-spec replace_process_image(task(), [iodata()]) -> ok | {error, eacces}.
replace_process_image(Task) ->
    replace_process_image(Task,
        alcove_drv:getopts([{depth, length(forkchain(Task))}])).
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

atexit(Task, Fun) when is_function(Fun, 3) ->
    gen_fsm:sync_send_event(Task, {atexit, Fun}, infinity).

%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================

init([Owner, init]) ->
    process_flag(trap_exit, true),
    case prx_drv:start_link() of
        {ok, Drv} ->
            gen_server:call(Drv, init, infinity),
            {ok, call_state, #state{drv = Drv, forkchain = [], owner = Owner}};
        Error ->
            {stop, Error}
    end;
init([Drv, Owner, Chain, fork, _Argv]) ->
    process_flag(trap_exit, true),
    case prx_drv:call(Drv, Chain, fork, []) of
        {ok, ForkChain} ->
            {ok, call_state, #state{drv = Drv, forkchain = ForkChain, owner = Owner}};
        {error, Error} ->
            {stop, Error}
    end;
init([Drv, Owner, Chain, clone, Flags]) ->
    process_flag(trap_exit, true),
    case prx_drv:call(Drv, Chain, clone, Flags) of
        {ok, ForkChain} ->
            {ok, call_state, #state{drv = Drv, forkchain = ForkChain, owner = Owner}};
        {error, Error} ->
            {stop, Error}
    end.

handle_event(_Event, StateName, State) ->
    {next_state, StateName, State}.

handle_sync_event(_Event, _From, StateName, State) ->
    {next_state, StateName, State}.

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
        atexit = Exit
    } = State) ->
    case maps:find(Task, Child) of
        error ->
            ok;
        {ok, Pid} ->

            [ Exit(Drv, ForkChain, child_to_map(X))
                    || X <- prx_drv:call(Drv, ForkChain, pid, []), X#alcove_pid.pid =:= Pid ]

    end,
    {next_state, call_state, State};

handle_info(Info, Cur, State) ->
    error_logger:error_report({info, Cur, Info}),
    {next_state, Cur, State}.

terminate(_Reason, _StateName, #state{drv = Drv, forkchain = []}) ->
    catch prx_drv:stop(Drv),
    ok;
terminate(_Reason, _StateName, #state{}) ->
    ok.

code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

% Stdin sent while the process is in call state is discarded.
call_state(_, State) ->
    {next_state, call_state, State}.

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
    } = State) when Call =:= execvp; Call =:= execve ->
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

exec_state({stdin, Buf}, #state{drv = Drv, forkchain = ForkChain} = State) ->
    prx_drv:stdin(Drv, ForkChain, Buf),
    {next_state, exec_state, State};

exec_state(_, State) ->
    {next_state, exec_state, State}.

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
    case Reply of
        {ok, Child} ->
            % Restore the child's signal handlers before calling exec()
            {ok, _} = sigaction(Child, sigint, Int),
            {ok, _} = sigaction(Child, sigquit, Quit),
            Stdout = system_exec(Child, Cmd),

            % Child has returned, restore the parent's signal handlers
            {ok, _} = sigaction(Task, sigint, Int),
            {ok, _} = sigaction(Task, sigquit, Quit),

            Stdout;
        Error ->
            {ok, _} = sigaction(Task, sigint, Int),
            {ok, _} = sigaction(Task, sigquit, Quit),
            Error
    end.

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
        500 ->
            list_to_binary(lists:reverse(Acc))
    end.

maybe_binary(N) when is_list(N) ->
    iolist_to_binary(N);
maybe_binary(N) when is_binary(N) ->
    N.

cloexec(Task, FD, Status) ->
    FD_CLOEXEC = call(Task, fcntl_define, [fd_cloexec]),
    {ok, Flags0} = fcntl(Task, FD, f_getfd),
    Flags1 = case Status of
        set -> Flags0 bor FD_CLOEXEC;
        unset -> Flags0 band (bnot FD_CLOEXEC)
    end,
    fcntl(Task, FD, f_setfd, Flags1).

%%%===================================================================
%%% Exported functions
%%%===================================================================

sandbox(Task) ->
    sandbox(Task, []).
sandbox(Task, Opt) ->
    Flags = proplists:get_value(flags, Opt, [
            clone_newnet,
            clone_newpid,
            clone_newipc,
            clone_newuts,
            clone_newns
        ]),

    Hostname = case proplists:get_value(hostname, Opt, fun(X) -> sethostname(X, name("###")) end) of
        H when is_function(H, 1) -> H;
        H when is_list(H); is_binary(H) -> fun(X) -> sethostname(X, H) end
    end,

    Umount = proplists:get_value(umount, Opt, fun(X) -> umount_all(X) end),
    Mount = proplists:get_value(mount, Opt, fun(X) -> mount_tmpfs(X, "/tmp", "4M") end),
    Chroot = proplists:get_value(chroot, Opt, fun(X) -> dochroot(X, "/tmp") end),

    Setid = case proplists:get_value(setid, Opt, fun(X) -> setid(X, id()) end) of
        I when is_function(I, 1) -> I;
        I when is_integer(I) -> fun(X) -> setid(X, I) end
    end,

    case prx:clone(Task, Flags) of
        {ok, Sandbox} ->
            Result = lists:foldl(fun
                    (_, {error,_} = Error) ->
                        Error;
                    (F, ok) ->
                        F(Sandbox)
                end,
                ok,
                [
                    Hostname,
                    Umount,
                    Mount,
                    Chroot,
                    Setid
                ]),
            case Result of
                {error, _} = Error ->
                    prx:stop(Task),
                    Error;
                ok ->
                    {ok, Sandbox}
            end;
        Error ->
            Error
    end.

umount_all(Task) ->
    ok = chdir(Task, "/"),
    {ok, Bin} = read_file(Task, "/proc/mounts"),
    Lines = binary:split(Bin, <<"\n">>, [global,trim]),
    Mounts = [ begin
                Fields = binary:split(Line, <<" ">>, [global,trim]),
                lists:nth(2, Fields)
        end || Line <- lists:reverse(Lines) ],
    [ umount(Task, Mount) || Mount <- Mounts ],
    ok.

read_file(Task, File) ->
    {ok, FD} = open(Task, File, [o_rdonly]),
    read_loop(Task, FD).

read_loop(Task, FD) ->
    read_loop(Task, FD, []).

read_loop(Task, FD, Acc) ->
    case read(Task, FD, 16#ffff) of
        {ok, <<>>} ->
            close(Task, FD),
            {ok, list_to_binary(lists:reverse(Acc))};
        {ok, Bin} ->
            read_loop(Task, FD, [Bin|Acc]);
        Error ->
            Error
    end.

mount_tmpfs(Task, Path, Size) ->
    mount(Task, "tmpfs", Path, "tmpfs", [
                ms_noexec,
                ms_nosuid,
                ms_rdonly
            ], <<"size=", (maybe_binary(Size))/binary, 0>>, <<>>).

dochroot(Task, Path) ->
    ok = chdir(Task, "/"),
    ok = chroot(Task, Path),
    chdir(Task, "/").

setid(Task, Id) ->
    ok = setresgid(Task, Id, Id, Id),
    setresuid(Task, Id, Id, Id).

id() ->
    16#f0000000 + crypto:rand_uniform(0, 16#ffff).

name(Name) ->
    Template = "0123456789abcdefghijklmnopqrstuvwxyz",
    Len = length(Template)+1,

    << <<case N of $# -> lists:nth(crypto:rand_uniform(1,Len),Template) ; _ -> N end>>
        || <<N:8>> <= maybe_binary(Name) >>.


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

-spec getrlimit(task(), constant()) -> {ok, #{cur => uint64_t(), max => uint64_t()}} | {error, file:posix()}.
getrlimit(Task, Resource) ->
    case call(Task, getrlimit, [Resource]) of
        {ok, #alcove_rlimit{cur = Cur, max = Max}} ->
            {ok, #{cur => Cur, max => Max}};
        Error ->
            Error
    end.

-spec setrlimit(task(), constant(), #{cur => uint64_t(), max => uint64_t()}) -> ok | {error, file:posix()}.
setrlimit(Task, Resource, Rlim) ->
    #{cur := Cur, max := Max} = Rlim,
    call(Task, setrlimit, [Resource, #alcove_rlimit{cur = Cur, max = Max}]).

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
-spec chdir(task(),iodata()) -> 'ok' | {'error', file:posix()}.
chdir(Task, Arg1) ->
    call(Task, chdir, [Arg1]).

-spec chmod(task(),iodata(),mode_t()) -> 'ok' | {'error', file:posix()}.
chmod(Task, Arg1, Arg2) ->
    call(Task, chmod, [Arg1, Arg2]).

-spec chown(task(),iodata(),uid_t(),gid_t()) -> 'ok' | {'error', file:posix()}.
chown(Task, Arg1, Arg2, Arg3) ->
    call(Task, chown, [Arg1, Arg2, Arg3]).

-spec chroot(task(),iodata()) -> 'ok' | {'error', file:posix()}.
chroot(Task, Arg1) ->
    call(Task, chroot, [Arg1]).

-spec clearenv(task()) -> 'ok' | {'error', file:posix()}.
clearenv(Task) ->
    call(Task, clearenv, []).

-spec close(task(),fd()) -> 'ok' | {'error', file:posix()}.
close(Task, Arg1) ->
    call(Task, close, [Arg1]).

-spec environ(task()) -> [binary()].
environ(Task) ->
    call(Task, environ, []).

-spec exit(task(),int32_t()) -> 'ok'.
exit(Task, Arg1) ->
    call(Task, exit, [Arg1]).

-spec fcntl(task(), fd(), constant()) -> {'ok',int64_t()} | {'error', file:posix()}.
-spec fcntl(task(), fd(), constant(), int64_t()) -> {'ok',int64_t()} | {'error', file:posix()}.
fcntl(Task, Arg1, Arg2) ->
    call(Task, fcntl, [Arg1, Arg2, 0]).

fcntl(Task, Arg1, Arg2, Arg3) ->
    call(Task, fcntl, [Arg1, Arg2, Arg3]).

-spec getcwd(task()) -> {'ok', binary()} | {'error', file:posix()}.
getcwd(Task) ->
    call(Task, getcwd, []).

-spec getenv(task(),iodata()) -> binary() | 'false'.
getenv(Task, Arg1) ->
    call(Task, getenv, [Arg1]).

-spec getgid(task()) -> gid_t().
getgid(Task) ->
    call(Task, getgid, []).

-spec getgroups(task()) -> {'ok', [gid_t()]} | {'error', file:posix()}.
getgroups(Task) ->
    call(Task, getgroups, []).

-spec gethostname(task()) -> {'ok', binary()} | {'error', file:posix()}.
gethostname(Task) ->
    call(Task, gethostname, []).

-spec getpgrp(task()) -> pid_t().
getpgrp(Task) ->
    call(Task, getpgrp, []).

-spec getpid(task()) -> pid_t().
getpid(Task) ->
    call(Task, getpid, []).

-spec getpriority(task(),constant(),int32_t()) -> {'ok',int32_t()} | {'error', file:posix()}.
getpriority(Task, Arg1, Arg2) ->
    call(Task, getpriority, [Arg1, Arg2]).

-spec getresgid(task()) -> {'ok', gid_t(), gid_t(), gid_t()} | {'error', file:posix()}.
getresgid(Task) ->
    call(Task, getresgid, []).

-spec getresuid(task()) -> {'ok', uid_t(), uid_t(), uid_t()} | {'error', file:posix()}.
getresuid(Task) ->
    call(Task, getresuid, []).

-spec getsid(task(),pid_t()) -> {'ok', pid_t()} | {'error', file:posix()}.
getsid(Task, Arg1) ->
    call(Task, getsid, [Arg1]).

-spec getuid(task()) -> uid_t().
getuid(Task) ->
    call(Task, getuid, []).

-spec ioctl(task(), fd(), constant(), cstruct()) -> {'ok',iodata()} | {'error', file:posix()}.
ioctl(Task, Arg1, Arg2, Arg3) ->
    call(Task, ioctl, [Arg1, Arg2, Arg3]).

-spec kill(task(),pid_t(),constant()) -> 'ok' | {'error', file:posix()}.
kill(Task, Arg1, Arg2) ->
    call(Task, kill, [Arg1, Arg2]).

-spec lseek(task(),fd(),off_t(),int32_t()) -> 'ok' | {'error', file:posix()}.
lseek(Task, Arg1, Arg2, Arg3) ->
    call(Task, lseek, [Arg1, Arg2, Arg3]).

-spec mkdir(task(),iodata(),mode_t()) -> 'ok' | {'error', file:posix()}.
mkdir(Task, Arg1, Arg2) ->
    call(Task, mkdir, [Arg1, Arg2]).

-spec mkfifo(task(),iodata(),mode_t()) -> 'ok' | {'error', file:posix()}.
mkfifo(Task, Arg1, Arg2) ->
    call(Task, mkfifo, [Arg1, Arg2]).

-spec mount(task(),iodata(),iodata(),iodata(),uint64_t() | [constant()],iodata()) -> 'ok' | {'error', file:posix()}.
-spec mount(task(),iodata(),iodata(),iodata(),uint64_t() | [constant()],iodata(),iodata()) -> 'ok' | {'error', file:posix()}.
mount(Task, Arg1, Arg2, Arg3, Arg4, Arg5) ->
    mount(Task, Arg1, Arg2, Arg3, Arg4, Arg5, <<>>).
mount(Task, Arg1, Arg2, Arg3, Arg4, Arg5, Arg6) ->
    call(Task, mount, [Arg1, Arg2, Arg3, Arg4, Arg5, Arg6]).

-spec open(task(),iodata(),int32_t() | [constant()]) -> {'ok',fd()} | {'error', file:posix()}.
-spec open(task(),iodata(),int32_t() | [constant()],mode_t()) -> {'ok',fd()} | {'error', file:posix()}.
open(Task, Arg1, Arg2) ->
    open(Task, Arg1, Arg2, 0).
open(Task, Arg1, Arg2, Arg3) ->
    call(Task, open, [Arg1, Arg2, Arg3]).

-spec pivot_root(task(),iodata(),iodata()) -> 'ok' | {'error', file:posix()}.
pivot_root(Task, Arg1, Arg2) ->
    call(Task, pivot_root, [Arg1, Arg2]).

-spec prctl(task(),constant(),cstruct(),cstruct(),cstruct(),cstruct()) -> {'ok',integer(),prctl_val(),prctl_val(),prctl_val(),prctl_val()} | {'error', file:posix()}.
prctl(Task, Arg1, Arg2, Arg3, Arg4, Arg5) ->
    call(Task, prctl, [Arg1, Arg2, Arg3, Arg4, Arg5]).

-spec read(task(),fd(),size_t()) -> {'ok', binary()} | {'error', file:posix()}.
read(Task, Arg1, Arg2) ->
    call(Task, read, [Arg1, Arg2]).

-spec readdir(task(),iodata()) -> {'ok', [binary()]} | {'error', file:posix()}.
readdir(Task, Arg1) ->
    call(Task, readdir, [Arg1]).

-spec rmdir(task(),iodata()) -> 'ok' | {'error', file:posix()}.
rmdir(Task, Arg1) ->
    call(Task, rmdir, [Arg1]).

-spec setenv(task(),iodata(),iodata(),int32_t()) -> 'ok' | {'error', file:posix()}.
setenv(Task, Arg1, Arg2, Arg3) ->
    call(Task, setenv, [Arg1, Arg2, Arg3]).

-spec setgid(task(),gid_t()) -> 'ok' | {'error', file:posix()}.
setgid(Task, Arg1) ->
    call(Task, setgid, [Arg1]).

-spec setgroups(task(), [gid_t()]) -> 'ok' | {'error', file:posix()}.
setgroups(Task, Arg1) ->
    call(Task, setgroups, [Arg1]).

-spec sethostname(task(),iodata()) -> 'ok' | {'error', file:posix()}.
sethostname(Task, Arg1) ->
    call(Task, sethostname, [Arg1]).

-spec setns(task(),iodata()) -> 'ok' | {'error', file:posix()}.
-spec setns(task(),iodata(),constant()) -> 'ok' | {'error', file:posix()}.
setns(Task, Arg1) ->
    setns(Task, Arg1, 0).
setns(Task, Arg1, Arg2) ->
    call(Task, setns, [Arg1, Arg2]).

-spec setpgid(task(),pid_t(),pid_t()) -> 'ok' | {'error', file:posix()}.
setpgid(Task, Arg1, Arg2) ->
    call(Task, setpgid, [Arg1, Arg2]).

-spec setpriority(task(),constant(),int32_t(),int32_t()) -> 'ok' | {'error', file:posix()}.
setpriority(Task, Arg1, Arg2, Arg3) ->
    call(Task, setpriority, [Arg1, Arg2, Arg3]).

-spec setresgid(task(),gid_t(),gid_t(),gid_t()) -> 'ok' | {'error', file:posix()}.
setresgid(Task, Arg1, Arg2, Arg3) ->
    call(Task, setresgid, [Arg1, Arg2, Arg3]).

-spec setresuid(task(),uid_t(),uid_t(),uid_t()) -> 'ok' | {'error', file:posix()}.
setresuid(Task, Arg1, Arg2, Arg3) ->
    call(Task, setresuid, [Arg1, Arg2, Arg3]).

-spec setsid(task()) -> {ok,pid_t()} | {error, file:posix()}.
setsid(Task) ->
    call(Task, setsid, []).

-spec setuid(task(),uid_t()) -> 'ok' | {'error', file:posix()}.
setuid(Task, Arg1) ->
    call(Task, setuid, [Arg1]).

-spec sigaction(task(),constant(),atom()) -> {'ok',atom()} | {'error', file:posix()}.
sigaction(Task, Arg1, Arg2) ->
    call(Task, sigaction, [Arg1, Arg2]).

-spec umount(task(),iodata()) -> 'ok' | {error, file:posix()}.
umount(Task, Arg1) ->
    call(Task, umount, [Arg1]).

-spec unlink(task(),iodata()) -> 'ok' | {error, file:posix()}.
unlink(Task, Arg1) ->
    call(Task, unlink, [Arg1]).

-spec unsetenv(task(),iodata()) -> 'ok' | {error, file:posix()}.
unsetenv(Task, Arg1) ->
    call(Task, unsetenv, [Arg1]).

-spec unshare(task(),int32_t() | [constant()]) -> 'ok' | {'error', file:posix()}.
unshare(Task, Arg1) ->
    call(Task, unshare, [Arg1]).

-spec write(task(),fd(),iodata()) -> {'ok', ssize_t()} | {'error', file:posix()}.
write(Task, Arg1, Arg2) ->
    call(Task, write, [Arg1, Arg2]).
