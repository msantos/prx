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

        stop/1,

        start_link/1, task/4,

        sh/2, cmd/2,
        setproctitle/2,
        sandbox/1, sandbox/2,
        id/0,
        name/1,

        setrlimit/3,
        getrlimit/2,
        select/5,
        pid/1,

        call/3,

        stdin/2,

        forkchain/1,
        drv/1
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

-type uint64_t() :: 0 .. 16#ffffffffffffffff.

-type int32_t() :: -16#7fffffff .. 16#7fffffff.
-type int64_t() :: -16#7fffffffffffffff .. 16#7fffffffffffffff.

-type pid_t() :: int32_t().
-type fd() :: int32_t().

-type constant() :: atom() | integer().

-record(state, {
        owner,
        drv,
        forkchain,
        child = #{}
    }).

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
%% Call wrappers: portability, convert records to maps
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

-spec pid(task()) -> [#{pid => pid_t(), exec => boolean(), fdctl => fd(),
            stdin => fd(), stdout => fd(), stderr => fd()}].
pid(Task) ->
    [ #{pid => Pid, exec => Ctl =:= -2, fdctl => Ctl, stdin => In, stdout => Out, stderr => Err}
        || #alcove_pid{pid = Pid, fdctl = Ctl, stdin = In, stdout = Out, stderr = Err} <- call(Task, pid, []) ].

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
select(Task, Readfds, Writefds, Exceptfds, Timeout) ->
    call(Task, select, [Readfds, Writefds, Exceptfds, Timeout]).

%%
%% Retrieve internal state
%%
-spec forkchain(task()) -> [pid_t()].
forkchain(Task) ->
    gen_fsm:sync_send_event(Task, forkchain, infinity).

-spec drv(task()) -> pid().
drv(Task) ->
    gen_fsm:sync_send_event(Task, drv, infinity).

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

handle_info({'EXIT', Task, _Reason}, call_state, #state{drv = Drv, forkchain = ForkChain, child = Child} = State) ->
    case maps:find(Task, Child) of
        error ->
            ok;
        {ok, Pid} ->
            [ begin
                prx_drv:call(Drv, ForkChain, close, [X#alcove_pid.stdout]),
                prx_drv:call(Drv, ForkChain, close, [X#alcove_pid.stdin]),
                prx_drv:call(Drv, ForkChain, close, [X#alcove_pid.stderr])
              end || X <- prx_drv:call(Drv, ForkChain, pid, []), X#alcove_pid.pid =:= Pid ]
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

call_state(drv, {Owner, _Tag}, #state{
        drv = Drv,
        owner = Owner
    } = State) ->
    {reply, Drv, call_state, State};

call_state(forkchain, {_Owner, _Tag}, #state{
        forkchain = ForkChain
    } = State) ->
    {reply, ForkChain, call_state, State};

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
    {ok, Int} = call(Task, sigaction, [sigint, sig_ign]),
    {ok, Quit} = call(Task, sigaction, [sigquit, sig_ign]),
    Reply = fork(Task),
    case Reply of
        {ok, Child} ->
            % Restore the child's signal handlers before calling exec()
            {ok, _} = call(Child, sigaction, [sigint, Int]),
            {ok, _} = call(Child, sigaction, [sigquit, Quit]),
            Stdout = system_exec(Child, Cmd),

            % Child has returned, restore the parent's signal handlers
            {ok, _} = call(Task, sigaction, [sigint, Int]),
            {ok, _} = call(Task, sigaction, [sigquit, Quit]),

            Stdout;
        Error ->
            {ok, _} = call(Task, sigaction, [sigint, Int]),
            {ok, _} = call(Task, sigaction, [sigquit, Quit]),
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

    Hostname = case proplists:get_value(hostname, Opt, fun(X) -> prx:call(X, sethostname, [name("###")]) end) of
        H when is_function(H, 1) -> H;
        H when is_list(H); is_binary(H) -> fun(X) -> prx:call(X, sethostname, [H]) end
    end,

    Umount = proplists:get_value(umount, Opt, fun(X) -> umount_all(X) end),
    Mount = proplists:get_value(mount, Opt, fun(X) -> mount_tmpfs(X, "/tmp", "4M") end),
    Chroot = proplists:get_value(chroot, Opt, fun(X) -> chroot(X, "/tmp") end),

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
    ok = prx:call(Task, chdir, ["/"]),
    {ok, Bin} = read_file(Task, "/proc/mounts"),
    Lines = binary:split(Bin, <<"\n">>, [global,trim]),
    Mounts = [ begin
                Fields = binary:split(Line, <<" ">>, [global,trim]),
                lists:nth(2, Fields)
        end || Line <- lists:reverse(Lines) ],
    [ prx:call(Task, umount, [Mount]) || Mount <- Mounts ],
    ok.

read_file(Task, File) ->
    {ok, FD} = prx:call(Task, open, [File, [o_rdonly], 0]),
    read_loop(Task, FD).

read_loop(Task, FD) ->
    read_loop(Task, FD, []).

read_loop(Task, FD, Acc) ->
    case prx:call(Task, read, [FD, 16#ffff]) of
        {ok, <<>>} ->
            prx:call(Task, close, [FD]),
            {ok, list_to_binary(lists:reverse(Acc))};
        {ok, Bin} ->
            read_loop(Task, FD, [Bin|Acc]);
        Error ->
            Error
    end.

mount_tmpfs(Task, Path, Size) ->
    prx:call(Task, mount, ["tmpfs", Path, "tmpfs", [
                ms_noexec,
                ms_nosuid,
                ms_rdonly
            ], <<"size=", (maybe_binary(Size))/binary, 0>>, <<>>]).

chroot(Task, Path) ->
    ok = prx:call(Task, chdir, ["/"]),
    ok = prx:call(Task, chroot, [Path]),
    prx:call(Task, chdir, ["/"]).

setid(Task, Id) ->
    ok = prx:call(Task, setresgid, [Id, Id, Id]),
    prx:call(Task, setresuid, [Id, Id, Id]).

id() ->
    16#f0000000 + crypto:rand_uniform(0, 16#ffff).

name(Name) ->
    Template = "0123456789abcdefghijklmnopqrstuvwxyz",
    Len = length(Template)+1,

    << <<case N of $# -> lists:nth(crypto:rand_uniform(1,Len),Template) ; _ -> N end>>
        || <<N:8>> <= maybe_binary(Name) >>.
