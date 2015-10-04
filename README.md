prx
===

An Erlang library for Unix process management and system programming
tasks.

Build
-----

    $ rebar3 compile

Usage
-----

~~~ erlang
{ok, Task} = prx:fork(),
ok = prx:execvp(Task, ["/bin/cat", "-n"],
prx:stdin(Task, "test\n"),
receive {stdout, Task, _} = Out -> Out end.
~~~

~~~ erlang
{ok, Task} = prx:fork(),
{ok, Child} = prx:fork(Task),
OSPid = prx:call(Child, getpid, []),
ok = prx:execvp(Child, ["/bin/cat", "-n"],
prx:stdin(Child, "test\n"),
receive {stdout, Child, _} = Out -> Out end.
~~~

~~~ erlang
application:set_env(prx, options, [{exec, "sudo -n"}]),
{ok, Task} = prx:fork(),
{ok, Child} = prx:clone(Task, [clone_newnet, clone_newpid, clone_newipc,
    clone_newuts, clone_newns]),
OSPid = prx:call(Child, getpid, []),
ok = prx:execvp(Child, ["/bin/cat", "-n"],
prx:stdin(Child, "test\n"),
receive {stdout, Child, _} = Out -> Out end.
~~~
