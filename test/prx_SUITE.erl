-module(prx_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("kernel/include/file.hrl").

-export([
        suite/0,
        all/0,
        groups/0,
        init_per_suite/1,
        end_per_suite/1,
        init_per_testcase/2,
        end_per_testcase/2
    ]).
-export([
        cpid/1,
        parent/1,
        clone_process_image_stress/1,
        eof/1,
        fork_jail_exec_stress/1,
        fork_process_image_stress/1,
        fork_stress/1,
        many_pid_to_one_task/1,
        no_os_specific_tests/1,
        ownership/1,
        pidof/1,
        prefork_exec_kill/1,
        prefork_exec_stress/1,
        prefork_stress/1,
        replace_process_image/1,
        replace_process_image_umount_proc/1,
        replace_process_image_env/1,
        replace_process_image_sh/1,
        stdin_blocked_exec/1,
        system/1,
        sh_signal/1,
        filter/1,
        port_exit/1
    ]).

-define(PIDSH,
"#!/bin/sh
set -e
while :; do
    echo $$
done
").
 
suite() ->
    Timeout = list_to_integer(os:getenv("PRX_TEST_TIMEOUT", "60")),
    [{timetrap, {seconds, Timeout}}].

all() ->
    {unix, OS} = os:type(),
    [{group, OS}, fork_stress, many_pid_to_one_task, prefork_stress,
        prefork_exec_stress, prefork_exec_kill, fork_process_image_stress,
        replace_process_image_env, system, replace_process_image_sh, sh_signal,
        pidof, cpid, parent, eof, ownership, stdin_blocked_exec, filter,
        port_exit].

groups() ->
    [
        {linux, [sequence], [
                clone_process_image_stress,
                replace_process_image,
                replace_process_image_umount_proc
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

end_per_suite(Config) ->
    Config.

init_per_testcase(Test, Config)
    when Test == clone_process_image_stress;
         Test == fork_jail_exec_stress;
         Test == replace_process_image_umount_proc ->
    Exec = os:getenv("PRX_TEST_EXEC", "sudo -n"),
    Ctldir = case os:getenv("PRX_TEST_CTLDIR") of
               false -> [];
               Dir -> [{ctldir, Dir}]
             end,
    application:set_env(prx, options, [{exec, Exec}] ++ Ctldir),
    {ok, Task} = prx:fork(),
    application:set_env(prx, options, []),
    [{Test, Task}|Config];
init_per_testcase(Test, Config) ->
    Ctldir = case os:getenv("PRX_TEST_CTLDIR") of
               false -> [];
               Dir -> [{ctldir, Dir}]
             end,
    application:set_env(prx, options, Ctldir),
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
    [] = waitpid(Task);
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
    [] = prx:cpid(Child),
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
    [] = prx:cpid(Task),
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
    [] =  waitpid(Task);
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
    case length(prx:cpid(Task)) of
        0 ->
            ok;
        _ ->
            timer:sleep(100),
            prefork_exec_kill_wait(Task)
    end.

prefork_exec_kill_loop(Task, X) ->
    case length(prx:cpid(Task)) of
        X ->
            [ prx:call(Task, kill, [maps:get(pid, Pid), 9]) || Pid <- prx:cpid(Task) ];
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
    [] =  prx:cpid(Task);
fork_jail_exec_stress_wait(Task, Ref, N) ->
    receive
        {ok, Ref} ->
            fork_jail_exec_stress_wait(Task, Ref, N-1);
        {error, Ref, Error} ->
            erlang:error([Error])
    end.

fork_jail_exec_stress_loop(Parent, Ref, Task, _JID, 0) ->
    ok = prx:call(Task, exit, [0]),
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
    ok = prx:replace_process_image(Child3, {fd, FD, Argv}, [""]),
    ok = case prx:environ(Child3) of
        [] -> ok;
        [<<>>] -> ok;
        Unexpected -> {error, Unexpected}
    end,

    ok.

%% $ egrep "/proc" /proc/self/mounts
%% proc /proc proc rw,relatime 0 0
%% systemd-1 /proc/sys/fs/binfmt_misc autofs rw,relatime,fd=35,pgrp=1,timeout=0,minproto=5,maxproto=5,direct 0 0
replace_process_image_umount_proc(Config) ->
    Task = ?config(replace_process_image_umount_proc, Config),

    {ok, Child} = prx:clone(Task, [
            clone_newipc,
            clone_newnet,
            clone_newns,
            clone_newpid,
            clone_newuts
        ]),

    ok = prx:mount(Child, "", "/", "", [
            ms_private
        ], <<>>),

    ok = prx:mount(Child, "", "/proc", "", [
            ms_private
        ], <<>>),

    _ = prx:mount(Child, "", "/proc/sys/fs/binfmt_misc", "", [
            ms_private
        ], <<>>),

    _ = prx:umount(Child, "/proc/sys/fs/binfmt_misc"),
    ok = prx:umount(Child, "/proc"),

    {error, enoent} = prx:open(Child, "/proc/self/mounts", [o_rdonly]),

    ok = prx:replace_process_image(Child),
    ok = prx:replace_process_image(Child).

% linux: replace_process_image fails {error, einval} if HOME is not set
% openbsd/freebsd: works
replace_process_image_env(Config) ->
    Task = ?config(replace_process_image_env, Config),
    ok = prx:clearenv(Task),
    case prx:replace_process_image(Task) of
        {error, einval} ->
            ok = prx:setenv(Task, "HOME", "/", 0),
            ok = prx:replace_process_image(Task);
        ok ->
            ok
    end.

replace_process_image_sh(Config) ->
    Task = ?config(replace_process_image_sh, Config),
    ok = prx:replace_process_image(Task),
    <<"test\n">> = prx:sh(Task, "echo \"test\"").

system(Config) ->
    Task = ?config(system, Config),
    <<"test\n">> = prx:cmd(Task, ["echo", "test"]),
    <<"test\n">> = prx:sh(Task, "echo \"test\""),

    % enable flow control and force the response to be split over several
    % messages by unbuffering the output
    true = prx:setopt(Task, flowcontrol, 1),
    _ = prx:sh(Task, "ps | grep --line-buffered .").

sh_signal(Config) ->
    Task = ?config(sh_signal, Config),
    {ok, Proc} = prx:fork(Task),
    <<>> = prx:sh(Proc, "sleep 2; kill $PPID; cat").

pidof(Config) ->
    Task0 = ?config(pidof, Config),
    {ok, Task1} = prx:fork(Task0),
    {ok, Task2} = prx:fork(Task1),

    Pid0 = prx:getpid(Task0),
    Pid1 = prx:getpid(Task1),
    Pid2 = prx:getpid(Task2),

    Pid0 = prx:pidof(Task0),
    Pid1 = prx:pidof(Task1),
    Pid2 = prx:pidof(Task2),

    prx:exit(Task2, 0),

    receive
        {exit_status, Task2, 0} ->
            noproc = prx:pidof(Task2)
    end,

    ok.

cpid(Config) ->
    Task0 = ?config(cpid, Config),
    {ok, Task1} = prx:fork(Task0),
    {ok, _Task2} = prx:fork(Task0),
    {ok, _Task3} = prx:fork(Task0),
    {ok, Task4} = prx:fork(Task0),
    {ok, _Task5} = prx:fork(Task0),

    Pid4 = prx:pidof(Task4),
    Child = prx:cpid(Task0, Task4),
    Child = prx:cpid(Task0, Pid4),
    #{pid := Pid4} = Child,

    -1 = prx:getopt(Task0, flowcontrol),
    true = prx:setopt(Task0, flowcontrol, 1),
    1 = prx:getopt(Task0, flowcontrol),

    -1 = prx:getcpid(Task1, flowcontrol),
    -1 = prx:getcpid(Task0, Task1, flowcontrol),
    15 = prx:getcpid(Task1, signaloneof),

    true = prx:setcpid(Task1, flowcontrol, 2),
    true = prx:setcpid(Task0, Task1, signaloneof, 9),

    2 = prx:getcpid(Task0, Task1, flowcontrol),
    9 = prx:getcpid(Task1, signaloneof),

    % exited child process
    ok = prx:exit(Task1, 0),
    receive
        {exit_status, Task1, 0} ->
            ok
    end,
    false = prx:getcpid(Task0, Task1, flowcontrol),
    false = prx:getcpid(Task1, signaloneof),

    false = prx:setcpid(Task0, Task1, flowcontrol, 1),
    false = prx:setcpid(Task1, signaloneof, 9),

    % "root" prx process
    false = prx:getcpid(Task0, flowcontrol),
    false = prx:getcpid(Task0, signaloneof),

    false = prx:setcpid(Task0, flowcontrol, 1),

    ok.

parent(Config) ->
    Task0 = ?config(parent, Config),
    {ok, Task1} = prx:fork(Task0),
    {ok, Task2} = prx:fork(Task1),
    {ok, Task3} = prx:fork(Task2),

    noproc = prx:parent(Task0),
    Task0 = prx:parent(Task1),
    Task1 = prx:parent(Task2),
    Task2 = prx:parent(Task3),

    ok.

eof(Config) ->
    Task0 = ?config(eof, Config),
    {ok, Task1} = prx:fork(Task0),
    ok = prx:execvp(Task1, ["/usr/bin/sort"]),
    prx:stdin(Task1, "ccc\n"),
    prx:stdin(Task1, "bbb\n"),
    prx:stdin(Task1, "aaa\n"),
    prx:eof(Task0, Task1),
    ok = receive
        {stdout, Task1, <<"aaa\nbbb\nccc\n">>} ->
            ok;
        N ->
            N
    end.

filter(Config) ->
    Ctrl = ?config(filter, Config),
    {ok, Task} = prx:fork(Ctrl),

    ok = prx:filter(Ctrl, [fork, execve, execvp]),
    {'EXIT',{undef,_}} = (catch prx:fork(Ctrl)),
    {ok, _} = prx:fork(Task),

    ok.

port_exit(Config) ->
    Port = ?config(port_exit, Config),
    {ok, Task} = prx:fork(Port),

    {error, eacces} = prx:exit(Port, 0),

    ok  = prx:exit(Task, 0),
    receive
        {exit_status, Task, 0} ->
            ok
    end,

    true = unlink(Port),
    ok  = prx:exit(Port, 0).

% Task Ownership
%
% If a process knows the pid of a prx:task(), it may request it to
% fork. The process owns the new task. Any other call results in an eacces
% exception.
%
% A process making a call after a task has called exec() will result in
% an eaccess exception.
ownership(Config) ->
    % Task0, Task1 are owned by this process
    Task0 = ?config(ownership, Config),
    {ok, Task1} = prx:fork(Task0),

    Pid = self(),
    % Fork a task owned by a new process
    spawn(fun() -> {ok, Task2} = prx:fork(Task1), Pid ! Task2 end),
    receive
        X ->
            {'EXIT', {eacces, _}} = (catch prx:getpid(X))
    end,

    % Call exec() and attempt a call
    {ok, Task3} = prx:fork(Task0),
    ok = prx:execvp(Task3, ["/bin/cat"]),
    {'EXIT', {eacces, _}} = (catch prx:getpid(Task3)),

    % Request a task with children to exec()
    {error, eacces} = prx:execvp(Task0, ["/bin/cat"]),

    ok.

stdin_blocked_exec(Config) ->
    Task0 = ?config(stdin_blocked_exec, Config),
    {ok, Task} = prx:fork(Task0),

    ok = prx:execvp(Task, ["sleep", "60"]),
    Stdin = binary:copy(<<"x">>, 10000),

    % Fill up the pipe buffer. On Linux, the capacity is 65535 bytes.
    [ ok = prx:stdin(Task, Stdin) || _ <- lists:seq(1,7) ],

    ok = receive
        {stdin, Task, {error, {eagain, N}}}  when N >= 0 ->
            ok;
        N ->
            N
    end.

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

waitpid(Task) ->
    Children = prx:cpid(Task),
    Pending = lists:splitwith(fun(T) -> maps:get(fdctl, T) < 0 end, Children),
    case Pending of
        {[], []} -> [];
        {_, []} -> waitpid(Task);
        Error -> Error
    end.
