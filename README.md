prx
===

An Erlang library for Unix process management and system programming
tasks.

prx provides:

* a safe interface to system calls and other POSIX operations that will
  not block the Erlang VM

* simple, reliable OS process management by mapping Erlang processes to
  a hierarchy of system processes

* an interface for privilege separation operations to restrict processes

* operations to isolate processes like containers and jails

Build
-----

    $ rebar3 compile

Quick Start
-----------

`prx` has two basic operations: fork and exec.

    % Spawn a new system process
    {ok, Task} = prx:fork(),
    
    % And a child of the process
    {ok, Child} = prx:fork(Task).

After fork()'ing, other calls can be made. For example:

    UID = prx:getuid(Task),
    PID = prx:getpid(Child).

Calling exec() causes the process I/O to be treated as streams of data:

    ok = prx:execvp(Child, ["/bin/cat", "-n"]),
    prx:stdin(Child, "test\n"),
    receive
        {stdout,Child,Stdout} ->
            Stdout
    end.

Usage
-----

    {ok, Task} = prx:fork(),
    ok = prx:execvp(Task, ["/bin/cat", "-n"],
    prx:stdin(Task, "test\n"),
    receive {stdout, Task, _} = Out -> Out end.

    {ok, Task} = prx:fork(),
    {ok, Child} = prx:fork(Task),
    OSPid = prx:call(Child, getpid, []),
    ok = prx:execvp(Child, ["/bin/cat", "-n"],
    prx:stdin(Child, "test\n"),
    receive {stdout, Child, _} = Out -> Out end.

    application:set_env(prx, options, [{exec, "sudo -n"}]),
    {ok, Task} = prx:fork(),
    {ok, Child} = prx:clone(Task, [clone_newnet, clone_newpid, clone_newipc,
        clone_newuts, clone_newns]),
    OSPid = prx:call(Child, getpid, []),
    ok = prx:execvp(Child, ["/bin/cat", "-n"],
    prx:stdin(Child, "test\n"),
    receive {stdout, Child, _} = Out -> Out end.

Documentation
-------------

https://github.com/msantos/prx/wiki
