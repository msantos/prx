%%% @copyright 2015-2016 Michael Santos <michael.santos@gmail.com>

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

-module(prx_drv).
-behaviour(gen_server).

-export([
        call/4,
        stdin/3,

        start_link/0,
        stop/1,

        progname/0
    ]).

% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).


-record(state, {
          drv :: pid(),
          port :: port(),
          fdexe :: prx:fd(),
          pstree = dict:new()
    }).

%% @doc Make a synchronous call into the port driver.
%%
%% The list of available calls and their arguments can be found here:
%%
%% [https://github.com/msantos/alcove#alcove-1]
%%
%% For example, to directly call `alcove:execve/5':
%%
%% ```
%% call(Drv, ForkChain, execve,
%%  ["/bin/ls", ["/bin/ls", "-al"], ["HOME=/home/foo"]])
%% '''
-spec call(pid(), [prx:pid_t()], atom(), list()) -> any().
call(PrxDrv, Chain, Call, Argv) when Call == fork; Call == clone ->
    gen_server:call(PrxDrv, {Chain, Call, Argv}, infinity);
call(PrxDrv, Chain, Call, Argv) ->
    Reply = gen_server:call(PrxDrv, {Chain, Call, Argv}, infinity),
    case Reply of
        true ->
            call_reply(PrxDrv, Chain, Call, infinity);
        Error ->
            Error
    end.

%% @doc Send standard input to process.
-spec stdin(pid(), [prx:pid_t()], iodata()) -> ok.
stdin(PrxDrv, Chain, Buf) ->
    gen_server:call(PrxDrv, {Chain, stdin, Buf}, infinity).

-spec stop(pid()) -> ok.
stop(PrxDrv) ->
    catch gen_server:stop(PrxDrv),
    ok.

%% @private
start_link() ->
    gen_server:start_link(?MODULE, [], []).

%% @private
init([]) ->
    process_flag(trap_exit, true),
    Progname = progname(),
    Options = application:get_env(prx, options, []) ++
        [{progname, Progname}, {ctldir, basedir(?MODULE)}],
    {ok, Drv} = alcove_drv:start_link(Options),
    {ok, #state{drv = Drv, fdexe = fdexe(Drv, Progname),
            port = alcove_drv:port(Drv)}}.

%% @private
handle_call(init, {Pid, _Tag}, #state{pstree = PS} = State) ->
    {reply, ok, State#state{pstree = dict:store([], Pid, PS)}};

handle_call(raw, {_Pid, _Tag}, #state{drv = Drv} = State) ->
    Reply = alcove_drv:raw(Drv),
    {reply, Reply, State};

handle_call(fdexe, _From, #state{fdexe = FD} = State) ->
    {reply, FD, State};

handle_call(port, _From, #state{port = Port} = State) ->
    {reply, Port, State};

handle_call({Chain0, Call, Argv}, {Pid, _Tag}, #state{
        drv = Drv,
        pstree = PS
    } = State) when Call =:= fork; Call =:= clone ->
    Data = alcove_codec:call(Call, Chain0, Argv),
    Reply = gen_server:call(Drv, {send, Data}, infinity),
    case Reply of
        true ->
            case call_reply(Drv, Chain0, Call, infinity) of
                {ok, Child} ->
                    erlang:monitor(process, Pid),
                    Chain = Chain0 ++ [Child],
                    {reply,
                     {ok, Chain},
                     State#state{pstree = dict:store(Chain, Pid, PS)}};
                {error, _} = Error ->
                    {reply, Error, State};
                Error ->
                    {reply, {prx_error, Error}, State}
            end;
        Error ->
            Error
    end;

handle_call({Chain, stdin, Buf}, {_Pid, _Tag}, #state{
        drv = Drv
    } = State) ->
    case alcove_drv:stdin(Drv, Chain, Buf) of
        true ->
            {reply, true, State};
        badarg ->
            {reply, {prx_error, badarg}, State}
    end;
handle_call({Chain, Call, Argv}, {_Pid, _Tag}, #state{
        drv = Drv
    } = State) ->
    Data = alcove_codec:call(Call, Chain, Argv),
    Reply = gen_server:call(Drv, {send, Data}, infinity),
    {reply, Reply, State}.

%% @private
handle_cast(_, State) ->
    {noreply, State}.

%% @private
handle_info({Event, Drv, Chain, Buf}, #state{
        drv = Drv,
        pstree = PS
    } = State) ->
    _ = case dict:find(Chain, PS) of
        error ->
            ok;
        {ok, Pid} ->
            Pid ! {Event, self(), Chain, Buf}
    end,
    {noreply, State};

handle_info({'DOWN', _MonitorRef, process, Pid, _Info}, #state{pstree = PS} = State) ->
    case dict:fold(fun(K,V,_) when V =:= Pid -> K; (_,_,A) -> A end, undefined, PS) of
        undefined ->
            {noreply, State};
        Chain ->
            PS1 = dict:filter(fun(Child, Task) ->
                        case lists:prefix(Chain, Child) of
                            true ->
                                erlang:exit(Task, kill),
                                false;
                            false ->
                                true
                        end
                end,
                PS),
            {noreply, State#state{pstree = PS1}}
    end;

handle_info({'EXIT', Drv, Reason}, #state{drv = Drv} = State) ->
    {stop, {shutdown, Reason}, State};

handle_info(Event, State) ->
    error_logger:info_report([{unhandled, Event}]),
    {noreply, State}.

%% @private
terminate(_Reason, #state{drv = Drv}) ->
    catch alcove_drv:stop(Drv),
    ok.

%% @private
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% @private
call_reply(Drv, Chain, exit, Timeout) ->
    receive
        {alcove_ctl, Drv, Chain, fdctl_closed} ->
            ok;
        {alcove_ctl, Drv, _Chain, badpid} ->
            erlang:error(badpid)
    after
        Timeout ->
            erlang:error(timeout)
    end;
call_reply(Drv, Chain, Call, Timeout) when Call =:= execve; Call =:= execvp; Call =:= fexecve ->
    receive
        {alcove_ctl, Drv, Chain, fdctl_closed} ->
            ok;
        {alcove_ctl, Drv, _Chain, badpid} ->
            erlang:error(badpid);
        {alcove_call, Drv, Chain, Event} ->
            Event
    after
        Timeout ->
            erlang:error(timeout)
    end;
call_reply(Drv, Chain, Call, Timeout) ->
    receive
        {alcove_ctl, Drv, Chain, fdctl_closed} ->
            call_reply(Drv, Chain, Call, Timeout);
        {alcove_event, Drv, Chain, {termsig,_} = Event} ->
            erlang:error(Event);
        {alcove_event, Drv, Chain, {exit_status,_} = Event} ->
            erlang:error(Event);
        {alcove_ctl, Drv, _Chain, badpid} ->
            erlang:error(badpid);
        {alcove_call, Drv, Chain, Event} ->
            Event
    after
        Timeout ->
            erlang:error(timeout)
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% @private
basedir(Module) ->
    case code:priv_dir(Module) of
        {error, bad_name} ->
            filename:join([
                filename:dirname(code:which(Module)),
                "..",
                "priv"
            ]);
        Dir ->
            Dir
        end.

%% @private
progname() ->
    filename:join([basedir(prx), "prx"]).

%% @private
fdexe(Drv, Progname) ->
    fdexe(Drv, Progname, os:type()).

%% @private
fdexe(Drv, Progname, {unix, OS}) when OS =:= freebsd; OS =:= linux ->
    {ok, FD} = alcove:open(Drv, [], Progname, [o_rdonly, o_cloexec], 0),
    FD;
fdexe(_, _, _) ->
    -1.
