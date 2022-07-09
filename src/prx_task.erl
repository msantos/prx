%%% @copyright 2016-2022 Michael Santos <michael.santos@gmail.com>

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

%% @doc Create a subprocess and run a sequence of operations.
%%
%% The `prx_task' module provides functions for creating a new process
%% from a `prx:task/0', running a series of operations on the subprocess
%% and cleaning up on error.  The new task is returned to the caller.
-module(prx_task).

-export([
    do/3, do/4,
    with/3
]).

-type op() ::
    {atom(), list()}
    | {module(), atom(), list()}
    | {module(), atom(), list(), [option()]}.

-type option() ::
    state
    | errexit
    | {state, boolean()}
    | {errexit, boolean()}
    | {transform, fun((any()) -> ok | {ok, State :: any()} | {error, prx:posix()})}.
%% Options to modify the behavior of an operation:
%%
%% * `state': pass `ok' result as the first parameter to the next
%%    operation (default: false)
%%
%% * `errexit': abort operations on error (default: true)
%%
%% * `transform': abort operations on error (default: true)

-type config() ::
    {init, fun((prx:task()) -> {ok, prx:task()} | {error, prx:posix()})}
    | {terminate, fun((prx:task(), prx:task()) -> any())}.

-export_type([
    op/0,
    option/0,
    config/0
]).

%% @doc Fork and configure a subprocess
%%
%% Returns a new process created using `prx:fork/0' after performing
%% the list of operations on the subprocess.
%%
%% If an operation returns an error, the process is terminated using
%% SIGKILL.
-spec do(prx:task(), [op() | [op()]], any()) -> {ok, prx:task()} | {error, prx:posix()}.
do(Parent, Ops, State) ->
    do(Parent, Ops, State, []).

%% @doc Fork and configure a subprocess
%%
%% Returns a new process created using the `init' function provided in the
%% `Config' argument list afer the process has run the list of
%% operations.
%%
%% If an operation fails, the subprocess is terminated using the
%% `terminate' function.
%%
%% If `init' or `terminate' functions are not provided, the default
%% functions are used.
%%
%% @see with/3
-spec do(prx:task(), [op() | [op()]], any(), [config()]) -> {ok, prx:task()} | {error, prx:posix()}.
do(Parent, Ops, State, Config) ->
    Init = proplists:get_value(init, Config, fun prx:fork/1),
    Terminate = proplists:get_value(terminate, Config, fun terminate/2),
    init(Parent, Init, Terminate, Ops, State).

terminate(Parent, Task) ->
    case prx:pidof(Task) of
        noproc ->
            prx:stop(Task);
        OSPid ->
            prx:stop(Task),
            prx:kill(Parent, OSPid, sigkill)
    end.

init(Parent, Init, Terminate, Ops, State) ->
    case Init(Parent) of
        {ok, Task} ->
            run(Parent, Task, Terminate, Ops, State);
        Error ->
            Error
    end.

run(Parent, Task, Terminate, Ops, State) ->
    case with(Task, Ops, State) of
        ok ->
            {ok, Task};
        Error ->
            Terminate(Parent, Task),
            Error
    end.

%% @doc Run a sequence of operations on a task
%%
%% The `with' function runs a sequence of operations on a task. Operations
%% are tuples or list of tuples:
%%
%% * module name: optional if modifier not used, defaults to `prx'
%%
%% * module function
%%
%% * function arguments
%%
%% * modifier options (see `prx_task:option/0')
%%
%% ```
%% Setuid = true,
%% [
%%  % equivalent to prx:chdir("/")
%%  {chdir, ["/"]},
%%
%%  % equivalent to prx:setsid(), error is ignored
%%  {prx, setsid, [], [{errexit, false}]},
%%
%%  % the op list can contain op lists
%%  [
%%      case Setuid of
%%          true ->
%%              [
%%                  {setresgid, [65534, 65534, 65534]},
%%                  {setresuid, [65534, 65534, 65534]}
%%              ];
%%          false ->
%%              []
%%      end
%%  ]
%% ]
%% '''
%%
%% The called function must return one of:
%%
%% * `ok'
%%
%% * `{ok, any()}'
%%
%% * `{error, any()}'
%%
%% Any other value will return a `badop' tuple containing the failing
%% module, function and argument list.
%%
%% If the op returns an `ok' tuple, the second element can optionally
%% be passed as state to the next operation. The initial state can be
%% set using the `State' argument to `with/3'.
-spec with(prx:task(), Ops :: [op() | [op()]], State :: any()) ->
    ok
    | {error, any()}
    | {badop, {module(), atom(), list()}, [op()]}
    | {badarg, any()}.
with(_Task, [], _State) ->
    ok;
with(Task, [Op | Ops], State) when is_list(Op) ->
    case with(Task, Op, State) of
        ok ->
            with(Task, Ops, State);
        Error ->
            Error
    end;
with(Task, [{Fun, Arg} | Ops], State) ->
    op(Task, prx, Fun, [Task | Arg], [], Ops, State);
with(Task, [{Fun, Arg, Options} | Ops], State) when is_atom(Fun), is_list(Arg), is_list(Options) ->
    with(Task, [{prx, Fun, Arg, Options} | Ops], State);
with(Task, [{Mod, Fun, Arg} | Ops], State) when is_atom(Mod), is_atom(Fun) ->
    op(Task, Mod, Fun, [Task | Arg], [], Ops, State);
with(Task, [{Mod, Fun, Arg0, Options} | Ops], State) ->
    ArgvWithState = proplists:get_value(state, Options, false),
    Arg =
        case ArgvWithState of
            true -> [State, Task | Arg0];
            false -> [Task | Arg0]
        end,
    op(Task, Mod, Fun, Arg, Options, Ops, State);
with(_Task, [Op | _], _State) ->
    {badarg, Op}.

op(Task, Mod, Fun, Arg, Options, Ops, State) ->
    Exit = proplists:get_value(errexit, Options, true),
    Transform = proplists:get_value(transform, Options, fun(N) -> N end),
    try Transform(erlang:apply(Mod, Fun, Arg)) of
        ok ->
            with(Task, Ops, State);
        {ok, NewState} ->
            with(Task, Ops, NewState);
        Branch when is_list(Branch) ->
            with(Task, Branch, State);
        {error, _} when Exit =:= false ->
            with(Task, Ops, State);
        {error, _} = Error ->
            Error;
        _ ->
            {badop, {Mod, Fun, Arg}, Ops}
    catch
        _:_ ->
            {badop, {Mod, Fun, Arg}, Ops}
    end.
