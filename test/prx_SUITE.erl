-module(prx_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("kernel/include/file.hrl").

-export([
        all/0,
        groups/0,
        init_per_suite/1,
        init_per_testcase/2,
        end_per_testcase/2
    ]).
-export([
        fork_stress/1,
        many_pid_to_one_task/1,
        prefork_stress/1,
        prefork_exec_stress/1,
        prefork_exec_kill/1,
        fork_process_image_stress/1,
        clone_process_image_stress/1,
        fork_jail_exec_stress/1,
        replace_process_image/1,
        no_os_specific_tests/1
    ]).

-define(PIDSH,
"#!/bin/sh
set -e
while :; do
    echo $$
done
").
 
all() ->
    {unix, OS} = os:type(),
    [{group, OS}, fork_stress, many_pid_to_one_task, prefork_stress,
        prefork_exec_stress, prefork_exec_kill, fork_process_image_stress].

groups() ->
    [
        {linux, [], [
                clone_process_image_stress,
                replace_process_image
            ]},
        {freebsd, [], [
                fork_jail_exec_stress,
                replace_process_image
            ]},
        {darwin, [], [no_os_specific_tests]},
        {netbsd, [], [no_os_specific_tests]},
        {openbsd, [], [no_os_specific_tests]},
        {solaris, [], [no_os_specific_tests]}
    ].

init_per_suite(Config) ->
    DataDir = ?config(data_dir, Config),
    case file:make_dir(DataDir) of
        ok -> ok;
        {error,eexist} -> ok;
        Error -> erlang:error(Error)
    end,
    NTimes = os:getenv("PRX_TEST_NTIMES", "20"),
    NProcs = os:getenv("PRX_TEST_NPROCS", "10"),
    [{ntimes, list_to_integer(NTimes)},
        {nprocs, list_to_integer(NProcs)}|Config].

init_per_testcase(Test, Config)
    when Test == clone_process_image_stress;
         Test == fork_jail_exec_stress ->
    application:set_env(prx, options, [{exec, "sudo -n"}]),
    {ok, Task} = prx:fork(),
    application:set_env(prx, options, []),
    [{Test, Task}|Config];
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
fork_stress(Config) ->
    Task = ?config(fork_stress, Config),
    N = ?config(ntimes, Config),
    X = ?config(nprocs, Config),
    Ref = make_ref(),
    Self = self(),
    [ spawn(fun() -> fork_stress_loop(Self, Ref,Task,N) end) || _ <- lists:seq(1,X) ],
    fork_stress_wait(Ref,Task,X).

fork_stress_wait(_Ref,Task,0) ->
    [] = prx:children(Task);
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
    [] = prx:children(Child),
    ok = prx:call(Child, exit, [0]),
    fork_stress_loop(Parent, Ref, Task, N-1).

%%
%% Multiple Erlang processes sending stdin to 1 task
%%
%% The message length is chosen to be greater than the max message size.
%%
many_pid_to_one_task(Config) ->
    Task = ?config(many_pid_to_one_task, Config),
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

prefork_stress(Config) ->
    Task = ?config(prefork_stress, Config),
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
    [] = prx:children(Task),
    OSPid = prx:call(Task, getpid, []),
    prefork_stress_loop(Parent, Ref, Task, OSPid, N-1).

%%
%% Pre-fork and execv() stress test
%%
prefork_exec_stress(Config) ->
    Task = ?config(prefork_exec_stress, Config),
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
    [] =  prx:children(Task);
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
prefork_exec_kill(Config) ->
    Task = ?config(prefork_exec_kill, Config),
    X = ?config(nprocs, Config),
                                 
    [ spawn(fun() ->
                    {ok, Child} = prx:fork(Task),
                    ok = prx:execvp(Child, ["sleep", "99999"])
            end) || _ <- lists:seq(1,X) ],
    prefork_exec_kill_loop(Task, X),
    prefork_exec_kill_wait(Task).

prefork_exec_kill_wait(Task) ->
    case length(prx:children(Task)) of
        0 ->
            ok;
        _ ->
            timer:sleep(100),
            prefork_exec_kill_wait(Task)
    end.

prefork_exec_kill_loop(Task, X) ->
    case length(prx:children(Task)) of
        X ->
            [ prx:call(Task, kill, [maps:get(pid, Pid), 9]) || Pid <- prx:children(Task) ];
        _ ->
            timer:sleep(100),
            prefork_exec_kill_loop(Task, X)
    end.

%%
%% Create a forkchain, exec()'ing the port process
%%
fork_process_image_stress(Config) ->
    Task = ?config(fork_process_image_stress, Config),
    true = prx:call(Task, setopt, [maxforkdepth, 2048]),
    N = ?config(ntimes, Config),
    X = ?config(nprocs, Config),
    Ref = make_ref(),
    Self = self(),
    [ spawn(fun() -> fork_process_image_loop(Self, Ref,Task,N) end) || _ <- lists:seq(1,X) ],
    fork_process_image_wait(Ref,Task,X).

fork_process_image_wait(_Ref,_Task,0) ->
    ok;
fork_process_image_wait(Ref,Task,N) ->
    receive
        {ok, Ref} ->
            fork_process_image_wait(Ref,Task,N-1);
        Error ->
            erlang:error(Error)
    end.

fork_process_image_loop(Parent, Ref, _Task, 0) ->
    Parent ! {ok, Ref};
fork_process_image_loop(Parent, Ref, Task, N) ->
    {ok, Child} = prx:fork(Task),
    ok = prx:replace_process_image(Child),
    ok = prx:setproctitle(Child, io_lib:format("~p", [Child])),
    true = prx:call(Child, setopt, [maxforkdepth, 2048]),
    fork_process_image_loop(Parent, Ref, Child, N-1).

%%
%% Create a forkchain, exec()'ing the port process
%%
clone_process_image_stress(Config) ->
    Task = ?config(clone_process_image_stress, Config),
    true = prx:call(Task, setopt, [maxforkdepth, 2048]),
    N = ?config(ntimes, Config),
    X = ?config(nprocs, Config),
    Ref = make_ref(),
    Self = self(),
    [ spawn(fun() -> clone_process_image_loop(Self, Ref,Task,N) end) || _ <- lists:seq(1,X) ],
    clone_process_image_wait(Ref,Task,X).

clone_process_image_wait(_Ref,_Task,0) ->
    ok;
clone_process_image_wait(Ref,Task,N) ->
    receive
        {ok, Ref} ->
            clone_process_image_wait(Ref,Task,N-1);
        Error ->
            erlang:error(Error)
    end.

clone_process_image_loop(Parent, Ref, _Task, 0) ->
    Parent ! {ok, Ref};
clone_process_image_loop(Parent, Ref, Task, N) ->
    {ok, Child} = prx:clone(Task, [
            clone_newipc,
            clone_newnet,
            clone_newns,
            clone_newpid,
            clone_newuts
        ]),
    ok = prx:replace_process_image(Child),
    ok = prx:setproctitle(Child, io_lib:format("~p", [Child])),
    true = prx:call(Child, setopt, [maxforkdepth, 2048]),
    clone_process_image_loop(Parent, Ref, Child, N-1).

%%
%% Fork, jail() and execv() stress test
%%
fork_jail_exec_stress(Config) ->
    Task = ?config(fork_jail_exec_stress, Config),
    N = ?config(ntimes, Config),
    X = ?config(nprocs, Config),
    Ref = make_ref(),
    Self = self(),
    [ spawn(fun() ->
                    {ok, Child} = prx:fork(Task),
                    {ok, JID} = prx:jail(Child, #{path => "/rescue",
                                                  hostname => "prx" ++ integer_to_list(Num),
                                                  jailname => "jail" ++ integer_to_list(Num)}),
                    ok = prx:chdir(Child, "/"),
                    fork_jail_exec_stress_loop(Self, Ref, Child, JID, N)
            end) || Num <- lists:seq(1,X) ],
    fork_jail_exec_stress_wait(Task, Ref, X).

fork_jail_exec_stress_wait(Task, _Ref, 0) ->
    [] =  prx:children(Task);
fork_jail_exec_stress_wait(Task, Ref, N) ->
    receive
        {ok, Ref} ->
            fork_jail_exec_stress_wait(Task, Ref, N-1);
        {error, Ref, Error} ->
            erlang:error([Error])
    end.

fork_jail_exec_stress_loop(Parent, Ref, _Task, _JID, 0) ->
    Parent ! {ok, Ref};
fork_jail_exec_stress_loop(Parent, Ref, Task, JID, N) ->
    {ok, Child} = prx:fork(Task),
    ok = prx:execvp(Child, ["/nc", "-z", "8.8.8.8", "53"]),
    receive
        {exit_status, Child, 0} ->
            Parent ! {error, Ref, {fail, JID}};
        {exit_status, Child, _} ->
            fork_jail_exec_stress_loop(Parent, Ref, Task, JID, N-1)
    end.

%%
%% Replace process image using the path (execve) and a file descriptor
%% to the binary (fexecve)
%%
replace_process_image(Config) ->
    Task = ?config(replace_process_image, Config),

    {ok, Child1} = prx:fork(Task),
    ok = prx:replace_process_image(Child1),
    ok = prx:replace_process_image(Child1),

    Argv = alcove_drv:getopts([
            {progname, prx_drv:progname()},
            {depth, length(prx:forkchain(Task))}
        ]),
    {ok, Child2} = prx:fork(Task),
    ok = prx:replace_process_image(Child2, Argv, ["A=1"]),
    ok = prx:replace_process_image(Child2, Argv, []),
    [] = prx:environ(Child2),

    {ok, Child3} = prx:fork(Task),
    FD = gen_server:call(prx:drv(Task), fdexe),
    ok = prx:replace_process_image(Child3, {fd, FD, Argv}, ["A=1"]),
    ok = prx:replace_process_image(Child3, {fd, FD, Argv}, []),
    [] = prx:environ(Child3),

%    {ok, Child4} = prx:fork(Task),
%    FD = gen_server:call(prx:drv(Task), fdexe),
%    ok = prx:close(Child4, FD),
%    ok = prx:replace_process_image(Child4),
%    ok = prx:replace_process_image(Child4),

    ok.

no_os_specific_tests(_Config) ->
    {skip, "No OS specific tests defined"}.

%%
%% Utilities
%%
mkscript(DataDir, File, Contents) ->
    Name = filename:join([DataDir, File]),
    ok = file:write_file(Name, Contents),
    ok = file:write_file_info(Name, #file_info{mode = 8#755}),
    Name.
