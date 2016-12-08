%%% @copyright 2016 Michael Santos <michael.santos@gmail.com>

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
-module(prx_task).

-export([
        do/3, do/4,
        with/3
    ]).

-type op() :: {function(), list()}
    | {module(), function(), list()}
    | {module(), function(), list(), [option()]}.

-type option() :: state | errexit
    | {state, boolean()}
    | {errexit, boolean()}
    | {transform,
       fun((any()) -> ok | {ok, State :: any()} | {error, prx:posix()})}.

-type config() ::
    {init,
        fun((prx:task()) -> {ok, prx:task()} | {error, prx:posix()})}
    | {terminate, fun((prx:task(), prx:task()) -> any())}.

-export_type([
              op/0,
              option/0,
              config/0
             ]).

-spec do(prx:task(), [op()|[op()]], any())
    -> {ok, prx:task()} | {error, prx:posix()}.
do(Parent, Ops, State) ->
    do(Parent, Ops, State, []).

-spec do(prx:task(), [op()|[op()]], any(), [config()])
    -> {ok, prx:task()} | {error, prx:posix()}.
do(Parent, Ops, State, Config) ->
    Init = proplists:get_value(init, Config, fun prx:fork/1),
    Terminate = proplists:get_value(terminate, Config, fun terminate/2),
    init(Parent, Init, Terminate, Ops, State).

terminate(Parent, Task) ->
    OSPid = prx:pidof(Task),
    prx:stop(Task),
    prx:kill(Parent, OSPid, sigkill).

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

-spec with(prx:task(), [op()|[op()]], any())
    -> ok
       | {error, any()}
       | {badop, {module(), function(), list()}, [op()]}
       | {badarg, any()}.
with(_Task, [], _State) ->
    ok;
with(Task, [Op|Ops], State) when is_list(Op) ->
    case with(Task, Op, State) of
        ok ->
            with(Task, Ops, State);
        Error ->
            Error
    end;
with(Task, [{Fun, Arg}|Ops], State) ->
    op(Task, prx, Fun, [Task|Arg], [], Ops, State);
with(Task, [{Mod, Fun, Arg}|Ops], State) ->
    op(Task, Mod, Fun, [Task|Arg], [], Ops, State);
with(Task, [{Mod, Fun, Arg0, Options}|Ops], State) ->
    ArgvWithState = proplists:get_value(state, Options, false),
    Arg = case ArgvWithState of
        true -> [State, Task|Arg0];
        false -> [Task|Arg0]
    end,
    op(Task, Mod, Fun, Arg, Options, Ops, State);
with(_Task, [Op|_], _State) ->
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
