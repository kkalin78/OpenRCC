%Module
-module(open_rcc_server).

%Behaviour
-behaviour(gen_server).

%Start Function
-export([start_link/1, mochiweb_loop/1]).

%Gen_Server API
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-record(state, {} ). %Empty for now.

%OpenACD
-include_lib("OpenACD/include/log.hrl").
-include_lib("OpenACD/include/call.hrl").
-include_lib("OpenACD/include/agent.hrl").
-include_lib("OpenACD/include/queue.hrl").
-include_lib("OpenACD/include/web.hrl").

-define(SERVER, ?MODULE).

-define(GET_USERNAME(QueryString), proplists:get_value("username", QueryString)).

%% HTTP routines and Responses
-define(CONTENT_HTML, [{"Content-Type", "text/html"}]).
-define(RESP_MISSED_USERNAME, {400, ?CONTENT_HTML, << "Please define username parameter" >>}).
-define(RESP_NOTLOGGED_USER, {400, ?CONTENT_HTML, <<"User is not logged in">>}).
-define(RESP_SUCCESS, {200, ?CONTENT_HTML, <<"Success.">>}).
-define(RESP_SUCCESS_PARAM(RES), {200, ?CONTENT_HTML, atom_to_binary(RES, latin1)}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%% Gen_Server Stuff %%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

start_link(Port) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [Port], []).

init([Port]) ->
    start_mochiweb(Port),
    {ok, #state{}}.

handle_call({Resource, Req}, _From, State) ->
    QueryString = Req:parse_qs(),
    handle_request(Resource, QueryString, Req),
    {reply, ok, State}.

%% We need these to crash the process early if we starts using gen_cast&gen_info
%% somewhere in the code. But we cannot just remove them since the compiler
%% will show warnings abount unimplemented gen_server callbacks
handle_cast(undefined, State) ->
    {noreply, State}.
handle_info(undefined, State) ->
    {noreply, State}.

terminate(normal, _State) ->
    mochiweb_http:stop(),
    ok;
terminate(_Reason, _State) ->
    ok.

code_change(_, _, State) ->
    {ok, State}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%% Mochi-Web Stuff %%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

start_mochiweb(Port) ->
    ?INFO("Starting OpenRCC REST http handler. Listening port is ~p", [Port]),
    %% We need to do start_link there to link Mochiweb process into Supervision tree
    %% This process will die if Mochiweb process dies. 
    %% Thus Supervisor has an opportunity to restar boths. 
    mochiweb_http:start_link([{port, Port}, {loop, {?MODULE, mochiweb_loop}}]).

mochiweb_loop(Req) ->
    ?DEBUG("Start handeling of Request ~p", [Req]),
    Path = Req:get(path),
    Resource = case string:str(Path, "?") of
                   0 -> Path;
                   N -> string:substr(Path, 1, length(Path) - (N + 1))
               end,
    QueryString = Req:parse_qs(),
    handle_request(Resource, QueryString, Req).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% REST API %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% handle_request("/get_call_state", Req) ->
%%     QueryStringData = Req:parse_qs(),
%%     UserName = proplists:get_value("username", QueryStringData, ""), 
%%     case cpx:get_agent(UserName) of
%%         none -> 
%%             Req:respond({200, [{"Content-Type", "text/html"}], list_to_binary("Agent not logged in.")});
%%         Pid ->
%%             Agent = agent:dump_state(Pid),
%%             #agent{used_channels = Channels} = Agent,
            
%%             case dict:fetch_keys(Channels) of
%%                 [ChannelID] ->
%%                     {status, _Pid, {module, _Module}, [_PDict, _SysState, _Parent, _Dbg, Misc]} = sys:get_status(ChannelID),
%%                     [_, {data,[ _Tuple1, _Tuple2, _Tuple3,{"StateName", Data}]}, _] = Misc,
%%                     Req:respond({200, [{"Content-Type", "text/html"}], list_to_binary(io_lib:format("~p",[Data]))});
%%                 _ ->
%%                     Req:respond({200, [{"Content-Type", "text/html"}], list_to_binary("Agent not on call.")})
%%             end
%%     end;
    

%% handle_request("/get_release_state", Req) ->
%%     QueryStringData = Req:parse_qs(),
%%     UserName = proplists:get_value("username", QueryStringData, ""),
%%     case cpx:get_agent(UserName) of
%%         none -> 
%%             Req:respond({200, [{"Content-Type", "text/html"}], list_to_binary("Agent not logged in.")});
%%         Pid ->
%%             Agent = agent:dump_state(Pid),
%%             ReleaseData = Agent#agent.release_data,
%%             Req:respond({200, [{"Content-Type", "text/html"}], list_to_binary(io_lib:format("~p", [ReleaseData]))})
%%     end;

handle_request("/agents", _QueryString, Req) ->
    Data = cpx:get_agents(),
    Req:respond({200, [{"Content-Type", "text/html"}], list_to_binary(lists:flatten(io_lib:format("~p", [Data])))});

handle_request("/clients", _QueryString, Req) ->
    Data = call_queue_config:get_clients(),
    Req:respond({200, [{"Content-Type", "text/html"}], list_to_binary(lists:flatten(io_lib:format("~p", [Data])))});

handle_request("/queues", _QueryString, Req) ->
    Data = call_queue_config:get_queues(),
    Req:respond({200, [{"Content-Type", "text/html"}], list_to_binary(lists:flatten(io_lib:format("~p", [Data])))});

handle_request("/ringtest/" ++ Agent, _QueryString, Req) ->
    AgentPid = cpx:get_agent(Agent),
    AgentRec = agent:dump_state(AgentPid),
    Callrec = #call{id = "unused", source = self(), callerid= {"Echo test", "0000000"}},
    
    Req:respond({200, [{"Content-Type", "text/html"}], list_to_binary(lists:flatten(io_lib:format("~p~p~p", [AgentPid, AgentRec, Callrec])))}),

    Data = freeswitch_media_manager:ring_agent_echo(AgentPid, AgentRec, Callrec, 60000),
    Req:respond({200, [{"Content-Type", "text/html"}], list_to_binary(lists:flatten(io_lib:format("~p", [Data])))});
    %Data = freeswitch_dialer:start(Node, Number, Exten, Skills, Client, Vars),

%freeswitch_media_manager:make_outbound_call("DCF", cpx:get_agent("742"), agent:dump_state(cpx:get_agent("742")#agent.login)

handle_request("/init_outbound/" ++ _Rest, _QueryString, Req) ->
    Req:respond({200, [{"Content-Type", "text/html"}], <<"NYI.">>});

handle_request("/dial" ++ _Rest, _QueryString, Req) ->
    Req:respond({200, [{"Content-Type", "text/html"}], <<"NYI.">>});


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%  Node = 'freeswitch@127.0.0.1',
%%  Username = "200",
%%  Apid = cpx:get_agent(Username),
%%  ClientName = "DCF",
%%  Number = "1000",
%%  DS = "sofia/sipxdev3.patlive.local/" ++ "\$1" ++ "@sipxdev3.patlive.local",
%%  %{ok, Pid} = freeswitch_media_manager:make_outbound_call(ClientName, cpx:get_agent(Apid), Username),
%%  {ok, Pid} = freeswitch_outbound:start(Node, Username, Apid, ClientName, DS, 30),
%% 
%%  Call = freeswitch_media:get_call(Pid),
%%      %cdr:dialoutgoing(Call, Number),
%% 
%%  Fnode = 'freeswitch@127.0.0.1',
%%  ?NOTICE("I'm supposed to dial ~p for ~p", [Number, Call#call.id]),
%%  Self = self(),
%%  AgentRec = agent:dump_state(Apid),
%%  DialString = freeswitch_media_manager:get_agent_dial_string(AgentRec, []),
%%  F = fun(RingUUID) ->
%%          fun(ok, _Reply) ->
%%                  Client = Call#call.client,
%%                  CalleridArgs = case proplists:get_value(<<"callerid">>, Client#client.options) of
%%                      undefined ->
%%                          ["origination_privacy=hide_namehide_number"];
%%                      CalleridNum ->
%%                          ["origination_caller_id_name='"++Client#client.label++"'", "origination_caller_id_number='"++binary_to_list(CalleridNum)++"'"]
%%                  end,
%% 
%%                  freeswitch:bgapi(Fnode, uuid_setvar, RingUUID ++ " ringback %(2000,4000,440.0,480.0)"),
%%                  %freeswitch:bgapi(Fnode, uuid_setvar, RingUUID ++ " ringback tone_stream://path=/usr/local/freeswitch/conf/tetris.ttml;loops=10"),
%% 
%%                  freeswitch:sendmsg(Fnode, RingUUID,
%%                      [{"call-command", "execute"},
%%                          {"execute-app-name", "bridge"},
%%                          {"execute-app-arg", freeswitch_media_manager:do_dial_string(DS, Number, ["origination_uuid="++Call#call.id | CalleridArgs])}]),
%%                  Self ! {connect_uuid, Number};
%%              (error, Reply) ->
%%                  ok
%%          end
%%  end,
%%  RecPath = case cpx_supervisor:get_archive_path(Call) of
%%      none ->
%%          ?DEBUG("archiving is not configured for ~p", [Call#call.id]),
%%          undefined;
%%      {error, _Reason, Path} ->
%%          ?WARNING("Unable to create requested call archiving directory for recording ~p for ~p", [Path, Call#call.id]),
%%          undefined;
%%      Path ->
%%          Path++".wav"
%%  end,
%% 
%%  F2 = fun(_RingUUID, EventName, _Event, InState) ->
%%          case EventName of
%%              "CHANNEL_BRIDGE" ->
%%                  agent:conn_cast(Apid, {mediaload, Call, [{<<"height">>, <<"300px">>}]}),
%%                  ?DEBUG("archiving ~p to ~s.wav", [Call#call.id, RecPath]),
%%                  freeswitch:api(Fnode, uuid_setvar, Call#call.id ++ " RECORD_APPEND true"),
%%                  freeswitch:api(Fnode, uuid_record, Call#call.id ++ " start "++RecPath),
%%                  Self ! bridge;
%%              _ ->
%%                  ok
%%          end,
%%          {noreply, InState}
%%  end,
%%  F(Call#call.id),
%% 
%%  case freeswitch_ring:start(Fnode, [{handle_event, F2}], [{call, Call}, {agent, "200"}, {dialstring, DS}, {destination, Number}, no_oncall_on_bridge, {needed_events, ['CHANNEL_BRIDGE']}]) of
%%      {ok, Pid2} ->
%%          link(Pid2),
%%          cdr:dialoutgoing(Call, Number);
%%      {error, Error} ->
%%          ?ERROR("error creating ring channel for ~p:  ~p; agent:  ~s", [Call#call.id, Error, AgentRec#agent.login])
%%  end,
%%  Req:respond({200, [{"Content-Type", "text/html"}], <<"Success.">>});
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

handle_request("/spy" ++ _Rest, _QueryString, Req) ->
    Req:respond({200, [{"Content-Type", "text/html"}], <<"NYI.">>});
    
handle_request("/hangup" ++ _Rest, _QueryString, Req) ->
    Req:respond({200, [{"Content-Type", "text/html"}], <<"NYI.">>});

handle_request("/transfer" ++ _Rest, _QueryString, Req) ->
    Req:respond({200, [{"Content-Type", "text/html"}], <<"NYI.">>});

handle_request("/login" ++ _Rest, QueryString, Req) ->
    User = ?GET_USERNAME(QueryString),
    Password = proplists:get_value("password", QueryString),
    Respond = handle_login(agent_manager:query_agent(User), User, 
                           {Password, parse_endpoint(User, QueryString)}),
    Req:respond(Respond);

handle_request("/logout" ++ _Rest, QueryString, Req) ->
    Respond = find_agent_and_apply(?GET_USERNAME(QueryString), fun handle_logout/3, []),                   
    Req:respond(Respond);

handle_request("/set_avail" ++ _Rest, QueryString, Req) ->
    Respond = find_agent_and_apply(?GET_USERNAME(QueryString), 
                                   fun(Pid, _UserName, _Args) ->
                                           ?RESP_SUCCESS_PARAM(agent_connection:set_state(Pid, idle))
                                           end, []),
    Req:respond(Respond);

handle_request("/set_released" ++ _Rest, QueryString, Req) ->
    Reason = get_released_reason(QueryString),
    Respond = find_agent_and_apply(?GET_USERNAME(QueryString),
                                   fun(Pid, _UserName, _Reason) ->
                                           ?RESP_SUCCESS_PARAM(agent_connection:set_state(Pid, Reason))
                                           end, Reason),
    Req:respond(Respond);

handle_request("/hang_up" ++ _Rest, QueryString, Req) ->
    Respond = find_agent_and_apply(?GET_USERNAME(QueryString),
                                   fun(Pid, _UserName, _Args) ->
                                           ?RESP_SUCCESS_PARAM(agent_connection:set_state(Pid, wrapup))
                                           end, []),
    Req:respond(Respond);

handle_request("/end_wrapup" ++ _Rest, QueryString, Req) ->
    Respond = find_agent_and_apply(?GET_USERNAME(QueryString),
                                   fun(Pid, _UserName, _Args) ->
                                           ?RESP_SUCCESS_PARAM(agent_connection:set_state(Pid, idle))
                                           end, []),
    Req:respond(Respond);
    
handle_request(_Path, _QueryString, Req) ->
    Req:respond({404, ?CONTENT_HTML, <<"Not Found">>}).

%% handle_request("/end_wrapup" ++ _Rest, Req) ->
%%     QueryStringData = Req:parse_qs(),
%%     UserName = proplists:get_value("username", QueryStringData, ""),
    
%%     case cpx:get_agent(UserName) of
%%         none -> 
%%             Req:respond({200, [{"Content-Type", "text/html"}], list_to_binary("Agent not logged in.")});
%%         Pid ->
%%             Agent = agent:dump_state(Pid),
%%             #agent{used_channels = Channels} = Agent,

%%             case dict:fetch_keys(Channels) of
%%                 [ChannelID] ->
%%                     agent_channel:end_wrapup(ChannelID),
%%                     Req:respond({200, [{"Content-Type", "text/html"}], list_to_binary("Success.")});
%%                 Else ->
%%                     Req:respond({200, [{"Content-Type", "text/html"}], list_to_binary("Failure.")})
%%             end
%%     end;

%% handle_request("/get_channels" ++ _Rest, Req) ->
%%     QueryStringData = Req:parse_qs(),
%%     UserName = proplists:get_value("username", QueryStringData, ""), 
    
%%     case cpx:get_agent(UserName) of
%%         none -> 
%%             Req:respond({200, [{"Content-Type", "text/html"}], list_to_binary("Agent not logged in.")});
%%         Pid ->
%%             Agent = agent:dump_state(Pid),
%%             #agent{used_channels = Channels} = Agent,
%%             List =dict:fetch_keys(Channels),
%%             Req:respond({200, [{"Content-Type", "text/html"}], list_to_binary(io_lib:format("~p",[List]))})
%%     end;

%% handle_request("/get_voice_channel" ++ _Rest, Req) ->
%%     QueryStringData = Req:parse_qs(),
%%     UserName = proplists:get_value("username", QueryStringData, ""), 
    
%%     case cpx:get_agent(UserName) of
%%         none -> 
%%             Req:respond({200, [{"Content-Type", "text/html"}], list_to_binary("Agent not logged in.")});
%%         Pid ->
%%             Agent = agent:dump_state(Pid),
%%             #agent{used_channels = Channels} = Agent,
            
%%             [ChannelID] = dict:fetch_keys(Channels),
%%             Req:respond({200, [{"Content-Type", "text/html"}], list_to_binary(io_lib:format("~p",[ChannelID]))})
%%     end;

get_released_reason(QueryString) ->
    Id = proplists:get_value("id", QueryString),
    Label = proplists:get_value("label", QueryString),
    Bias = proplists:get_value("bias", QueryString),
    get_released_reason(Id, Label, Bias).

get_released_reason(undefined, _, _) ->
    {released, default};
get_released_reason(_, undefined, _) ->
    {released, default};
get_released_reason(_, _, undefined) ->
    {released, default};
get_released_reason(Id, Label, Bias) ->
    {released, {Id, Label, list_to_integer(Bias)}}.

handle_logout(Pid, _User, _Args) when is_pid(Pid) ->
    agent_connection:stop(Pid),
    {200, ?CONTENT_HTML, << "Success" >>}.

handle_login(false, UserName, {Password, Endpoint}) ->
    agent_login(UserName, Password, Endpoint);
handle_login(Pid, UserName, _Args) ->
    {200, ?CONTENT_HTML, list_to_binary(
                           io_lib:format("~p is already logged in. Pid=~p", [UserName, Pid])
                          )}.

agent_login(UserName, Password, Endpoint) ->
    case agent_auth:auth(UserName, Password) of
        {allow, Id, Skills, Security, Profile} ->
            Agent = #agent{
              id = Id, 
              login = UserName, 
              skills = Skills, 
              profile=Profile, 
              security_level = Security
             },
            {ok, Pid} = agent_connection:start(Agent),
            agent_connection:set_endpoint(Pid, Endpoint),
            {200, ?CONTENT_HTML, << "Success" >>};
        deny ->
            {403, ?CONTENT_HTML, << "Agent is not found or invalid password" >>}
    end.

parse_endpoint(UserName, QueryString) ->
    %% TODO - Need to be verified with different types.
    EndpointType = proplists:get_value(endpointtype, QueryString, sip_registration),
    EndpointData = proplists:get_value(endpointdata, QueryString, UserName),
    {EndpointType, EndpointData}.

find_agent_and_apply(undefined, _Function, _Args) ->
    ?RESP_MISSED_USERNAME;
find_agent_and_apply(UserName, Function, Args) ->
    case agent_manager:query_agent(UserName) of 
        false ->
            ?RESP_NOTLOGGED_USER;
        {true, Pid} ->
            % Ugly code, but it's easiest way to do it for now
            #agent{connection=CPid} = agent:dump_state(Pid),
            Function(CPid, UserName, Args)
    end.
