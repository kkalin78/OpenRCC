%%%-------------------------------------------------------------------
%%% @author Konstantin Kalin <kkalin@kkalin-macbook>
%%% @copyright (C) 2012, Konstantin Kalin
%%% @doc
%%% Agent connection for OpenRCC. OpenACD expects to have an agent linked 
%%% with Agent connection.
%%% @end
%%% Created : 13 May 2012 by Konstantin Kalin <kkalin@kkalin-macbook>
%%%-------------------------------------------------------------------
-module(agent_connection).

-behaviour(gen_server).

-include_lib("OpenACD/include/log.hrl").
-include_lib("OpenACD/include/call.hrl").
-include_lib("OpenACD/include/agent.hrl").

%% API
-export([
         start/1,
         get_agentpid/1,
         set_endpoint/2,
         set_endpoint/3,
         set_state/2,
         set_state/3,
         stop/1,
         queue_transfer/2,
         agent_transfer/2,
         media_command/2
        ]).

%% gen_fsm callbacks
-export([
         init/1, 
         handle_cast/2, 
         handle_info/2, 
         handle_call/3, 
         terminate/2, 
         code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {
          agent_pid :: pid()
         }).

%%%===================================================================
%%% API
%%%===================================================================

start(Agent) ->
    gen_server:start(?MODULE, [Agent], []).

-spec get_agentpid(pid()) -> pid().
get_agentpid(Pid) ->
    gen_server:call(Pid, get_agentpid).

-spec set_endpoint(pid(), {_, _}) -> any().
set_endpoint(Pid, Endpoint) ->
    gen_server:call(Pid, {set_endpoint, Endpoint}).

-spec set_endpoint(pid(), {atom(), list()}, atom()) -> any().
set_endpoint(Pid, Endpoint, Persistantness) ->
    gen_server:call(Pid, {set_endpoint, Endpoint, Persistantness}).

-spec set_state(pid(), string() | atom()) -> any().
set_state(Pid, Statename) ->
    gen_server:call(Pid, {set_state, Statename}).

-spec set_state(pid(), string() | atom(), any()) -> any().
set_state(Pid, Statename, Statedata) ->
    gen_server:call(Pid, {set_state, Statename, Statedata}).

-spec stop(pid()) -> none().
stop(Pid) ->
    gen_server:cast(Pid, stop).

-spec queue_transfer(pid(), string()) -> any().
queue_transfer(Pid, QueueName) ->
    gen_server:call(Pid, {queue_transfer, QueueName}).

-spec agent_transfer(pid(), string()) -> any().
agent_transfer(Pid, Transferee) ->
    gen_server:call(Pid, {agent_transfer, Transferee}).

-spec media_command(pid(), tuple()) -> any().
media_command(Pid, Command) ->
    gen_server:call(Pid, {media_cmd, Command}).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
init([Agent]) ->
    {ok, Pid} = agent_manager:start_agent(Agent),
    agent:set_connection(Pid, self()),
    {ok, #state{agent_pid=Pid}}.

handle_cast(stop, #state{agent_pid=Pid}=State) ->
    agent:stop(Pid),
    {stop, normal, State};
handle_cast(Msg, State) ->
    ?DEBUG("Got cast message ~p; State=~p. Ignoring...", [Msg, State]),
    {noreply, State}.

handle_info(Msg, State) ->
    ?DEBUG("Got info message ~p; State=~p. Ignoring...", [Msg, State]),
    {noreply, State}.

handle_call(get_agentpid, _From, #state{agent_pid=Pid}=State) ->
    {reply, Pid, State};

handle_call({set_endpoint, {EndpointType, EndpointData}}, _From, #state{agent_pid=Pid}=State) ->
    Reply = agent:set_endpoint(Pid, EndpointType, EndpointData),
    {reply, Reply, State};
handle_call({set_endpoint, {EndpointType, EndpointData}, Persistantness}, _From, #state{agent_pid=Pid}=State)->
    Reply = agent:set_endpoint(Pid, EndpointType, EndpointData, Persistantness),
    {reply, Reply, State};

handle_call({set_state, Statename}, From, State) when is_list(Statename) ->
    handle_call({set_state, agent:list_to_state(Statename)}, From, State);
handle_call({set_state, Statename}, _From, #state{agent_pid=Pid}=State) when is_atom(Statename) ->
    Reply = agent:set_state(Pid, Statename),
    {reply, Reply, State};

handle_call({set_state, {Statename, Statedata}}, From, State) when is_list(Statename) ->
    handle_call({set_state, agent:list_to_state(Statename), Statedata}, From, State);
handle_call({set_state, {Statename, Statedata}}, _From, #state{agent_pid=Pid}=State) when is_atom(Statename) ->
    Reply = agent:set_state(Pid, Statename, Statedata),
    {reply, Reply, State};

handle_call({queue_transfer, QueueName}, _From, #state{agent_pid=Pid}=State) when is_list(QueueName) ->
    Reply = agent:queue_transfer(Pid, QueueName),
    {reply, Reply, State};

handle_call({agent_transfer, Transferee}, _From, #state{agent_pid=Pid}=State) when is_list(Transferee) ->
    case agent_manager:query_agent(Transferee) of
        {true, Target} ->
            Reply = agent:agent_transfer(Pid, Target);
        false ->
            Reply = invalid
    end,
    {reply, Reply, State};

handle_call({media_cmd, {call, Cmd, Args}}, _From, #state{agent_pid=Pid}=State) ->
    case agent:dump_state(Pid) of 
        #agent{statedata=Call} when is_record(Call, call) ->
            {reply, gen_medial:call(Call#call.source, {Cmd, Args}), State};
        _Else ->
            {reply, invalid, State}
    end;

handle_call({media_cmd, {cast, Cmd, Args}}, _From, #state{agent_pid=Pid}=State) ->
    #agent{statedata=Call} = agent:dump_state(Pid),
    case agent:dump_state(Pid) of
        #agent{statedata=Call} when is_record(Call, call) ->
            gen_media:cast(Call#call.source, {Cmd, Args}),
            {reply, ok, State};
        _Else ->
            {reply, invalid, State}
    end.

terminate(_Reason, _State) ->
    ok.

code_change(_, _, State) ->
    {ok, State}.
