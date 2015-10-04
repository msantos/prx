-module(prx_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("kernel/include/file.hrl").

-export([all/0,init_per_suite/1,init_per_testcase/2,end_per_testcase/2]).
-export([
        fork_stress_test/1,
        many_pid_to_one_task_test/1,
        prefork_stress_test/1,
        prefork_exec_stress_test/1,
        prefork_exec_kill_test/1
    ]).

-define(PIDSH,
"#!/bin/sh
set -e
while :; do
    echo $$
done
").
 
all() -> [fork_stress_test, many_pid_to_one_task_test, prefork_stress_test,
    prefork_exec_stress_test, prefork_exec_kill_test].

init_per_suite(Config) ->
    DataDir = ?config(data_dir, Config),
    case file:make_dir(DataDir) of
        ok -> ok;
        {error,eexist} -> ok;
        Error -> erlang:error(Error)
    end,
    NTimes = os:getenv("PRX_TEST_NTIMES", "100"),
    NProcs = os:getenv("PRX_TEST_NPROCS", "20"),
    [{ntimes, list_to_integer(NTimes)},
        {nprocs, list_to_integer(NProcs)}|Config].

init_per_testcase(Test, Config) ->
    {ok, Task} = prx:fork(),
    [{Test, Task}|Config].

end_per_testcase(Test, Config) ->
    Task = ?config(Test, Config),
    prx:stop(Task),
    Config.
 
%%
%% Multiple Erlang processes forking Unix processes in a loop
%%
fork_stress_test(Config) ->
    Task = ?config(fork_stress_test, Config),
    N = ?config(ntimes, Config),
    X = ?config(nprocs, Config),
    Ref = make_ref(),
    Self = self(),
    [ spawn(fun() -> fork_stress_loop(Self, Ref,Task,N) end) || _ <- lists:seq(1,X) ],
    fork_stress_wait(Ref,Task,X).

fork_stress_wait(_Ref,Task,0) ->
    [] = prx:pid(Task);
fork_stress_wait(Ref,Task,N) ->
    receive
        {ok, Ref} ->
            fork_stress_wait(Ref,Task,N-1);
        Error ->
            erlang:error(Error)
    end.

fork_stress_loop(Parent, Ref, _Task, 0) ->
    Parent ! {ok, Ref};
fork_stress_loop(Parent, Ref, Task, N) ->
    {ok, Child} = prx:fork(Task),
    [] = prx:pid(Child),
    ok = prx:call(Child, exit, [0]),
    fork_stress_loop(Parent, Ref, Task, N-1).

%%
%% Multiple Erlang processes sending stdin to 1 task
%%
%% The message length is chosen to be greater than the max message size.
%%
many_pid_to_one_task_test(Config) ->
    Task = ?config(many_pid_to_one_task_test, Config),
    {ok, Child} = prx:fork(Task),
    ok = prx:execvp(Child, ["/bin/cat"]),
    N = ?config(ntimes, Config),
    X = ?config(nprocs, Config),
    Bin = iolist_to_binary([binary:copy(<<"x">>, 128), "\n"]),
    [ spawn(fun() -> many_pid_to_one_task_loop(Child, Bin, N) end) || _ <- lists:seq(1,X) ],
    many_pid_to_one_task_wait(Child, byte_size(Bin) * N * X).

many_pid_to_one_task_wait(_Task, 0) ->
    ok;
many_pid_to_one_task_wait(Task, N) ->
    receive
        {stdout, Task, Bin} ->
            many_pid_to_one_task_wait(Task, N - byte_size(Bin));
        Error ->
            erlang:error(Error)
    end.

many_pid_to_one_task_loop(_Task, _Bin, 0) ->
    ok;
many_pid_to_one_task_loop(Task, Bin, N) ->
    prx:stdin(Task, Bin),
    many_pid_to_one_task_loop(Task, Bin, N-1).

%%
%% Pre-fork processes
%%

prefork_stress_test(Config) ->
    Task = ?config(prefork_stress_test, Config),
    {ok, Child} = prx:fork(Task),
    N = ?config(ntimes, Config),
    X = ?config(nprocs, Config),
    Ref = make_ref(),
    Self = self(),
    [ spawn(fun() ->
                    {ok, Fork} = prx:fork(Child),
                    OSPid = prx:call(Fork, getpid, []),
                    prefork_stress_loop(Self, Ref, Fork, OSPid, N)
            end) || _ <- lists:seq(1,X) ],
    prefork_stress_wait(Ref,X).

prefork_stress_wait(_Ref,0) ->
    ok;
prefork_stress_wait(Ref,N) ->
    receive
        {ok, Ref, ok} ->
            prefork_stress_wait(Ref,N-1);
        {ok, Ref, Error} ->
            erlang:error(Error)
    end.

prefork_stress_loop(Parent, Ref, Task,_,0) ->
    Parent ! {ok, Ref, prx:call(Task, exit, [0])};
prefork_stress_loop(Parent, Ref, Task, OSPid, N) ->
    [] = prx:pid(Task),
    OSPid = prx:call(Task, getpid, []),
    prefork_stress_loop(Parent, Ref, Task, OSPid, N-1).

%%
%% Pre-fork and execv() stress test
%%
prefork_exec_stress_test(Config) ->
    Task = ?config(prefork_exec_stress_test, Config),
    DataDir = ?config(data_dir, Config),
    Script = mkscript(DataDir, "pid.sh", ?PIDSH),
    N = ?config(ntimes, Config),
    X = ?config(nprocs, Config),
    Ref = make_ref(),
    Self = self(),
    [ spawn(fun() ->
                    {ok, Child} = prx:fork(Task),
                    OSPid = prx:call(Child, getpid, []),
                    ok = prx:execvp(Child, [Script]),
                    prefork_exec_stress_loop(Self, Ref, Child, <<(integer_to_binary(OSPid))/binary, "\n">>, N)
            end) || _ <- lists:seq(1,X) ],
    prefork_exec_stress_wait(Task, Ref, X).

prefork_exec_stress_wait(Task, _Ref, 0) ->
    [] =  prx:pid(Task);
prefork_exec_stress_wait(Task, Ref, N) ->
    receive
        {ok, Ref} ->
            prefork_exec_stress_wait(Task, Ref, N-1);
        {error, Ref, Error} ->
            erlang:error(unexpected, [Error])
    end.

prefork_exec_stress_loop(Parent, Ref, Task, _OSPid, N) when N =< 0 ->
    prx:stop(Task),
    Parent ! {ok, Ref};
prefork_exec_stress_loop(Parent, Ref, Task, OSPid, N) ->
    receive
        {stdout, Task, Bin} ->
            Num = byte_size(Bin) div byte_size(OSPid),
            prefork_exec_stress_loop(Parent, Ref, Task, OSPid, N-Num);
        Error ->
            Parent ! {error, Ref, Error}
    end.

%%
%% Pre-fork processes, exec and kill
%%
prefork_exec_kill_test(Config) ->
    Task = ?config(prefork_exec_kill_test, Config),
    X = ?config(nprocs, Config),
                                 
    [ spawn(fun() ->
                    {ok, Child} = prx:fork(Task),
                    ok = prx:execvp(Child, ["sleep", "99999"])
            end) || _ <- lists:seq(1,X) ],
    prefork_exec_kill_loop(Task, X),
    prefork_exec_kill_wait(Task).

prefork_exec_kill_wait(Task) ->
    case length(prx:pid(Task)) of
        0 ->
            ok;
        _ ->
            timer:sleep(100),
            prefork_exec_kill_wait(Task)
    end.

prefork_exec_kill_loop(Task, X) ->
    case length(prx:pid(Task)) of
        X ->
            [ prx:call(Task, kill, [maps:get(pid, Pid), 9]) || Pid <- prx:pid(Task) ];
        _ ->
            timer:sleep(100),
            prefork_exec_kill_loop(Task, X)
    end.

%%
%% Utilities
%%
mkscript(DataDir, File, Contents) ->
    Name = filename:join([DataDir, File]),
    ok = file:write_file(Name, Contents),
    ok = file:write_file_info(Name, #file_info{mode = 8#755}),
    Name.
