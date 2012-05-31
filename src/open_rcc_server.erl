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

-define(MOCHI_WEB_HTTP, openrcc_http_mochi).
-define(MOCHI_WEB_HTTPS, openrcc_https_mochi).

%% HTTP routines and Responses
-define(CONTENT_JSON, [{"Content-Type", "application/json"}]).
-define(RESP_AGENT_NOT_LOGGED, {200, ?CONTENT_JSON, encode_response(<<"false">>, <<"Agent is not logged in">>)}).
-define(RESP_SUCCESS, {200, ?CONTENT_JSON, encode_response(<<"true">>)}).

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
    ?INFO("Starting OpenRCC REST http handler. Listening ports are HTTP ~p and HTTPS ~p", 
          [Port, Port + 1]),

    mochiweb_http:start([{port, Port}, 
                         {loop, {?MODULE, mochiweb_loop}},
                         {name, ?MOCHI_WEB_HTTP}
                        ]),

    mochiweb_http:start([
                         {name, ?MOCHI_WEB_HTTPS},
                         {port, Port + 1}, 
                         {ssl, true},
	 					 {ssl_opts, [
                                     {certfile, get_certfile()},
                                     {keyfile, get_keyfile()}
                                    ]},
                         {loop, {?MODULE, mochiweb_loop}}]).

mochiweb_loop(Req) ->
    ?DEBUG("Start handeling of Request ~p", [Req]),
    Path = Req:get(path),
    Resource = case string:str(Path, "?") of
                   0 -> Path;
                   N -> string:substr(Path, 1, length(Path) - (N + 1))
               end,
    QueryString = Req:parse_qs(),
    try 
        handle_request(Resource, QueryString, Req)
    catch
        %% There is always a posibility that agent or call process will die just before we call it
        %% Also REST call could have invalid PID and we cannot check it for sure since there is no
        %% clear way how to check PIDs on remote node
        exit:{noproc, _Rest} ->
            Req:respond({200, ?CONTENT_JSON, 
                         encode_response(<<"false">>, <<"Invalid PID or Agent process has died">>)})
    end.
    
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% REST API %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%--------------------------------------------------------------------
%% @doc
%% Login an agent in OpenACD. The agent will be unavaible state.
%%     HTTP request - <server:port>/login?agent=<agent name>&password=<password>&domain=<SIP domain>
%%         <agent name> - is an agent name.
%%         <password> - is password in plain text (Unsecured).
%%         <SIP domain> - SIP domain name
%%     The method can return:
%%         200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/login" ++ _Rest, QueryString, Req) ->
    Username = proplists:get_value("agent", QueryString, ""),
    Password = proplists:get_value("password", QueryString, ""),
    Domain = proplists:get_value("domain", QueryString, "config.acd.dcf.patlive.local"),
    
    %% Endpointdata = [ Username, "@", Domain | [] ],
    %% Endpointtype = pstn,
    %% Testing parameter
    Endpointdata =  Username,
    Endpointtype = sip_registration,

    Persistance = transient,
    Bandedness = outband,
    
    case agent_manager:query_agent(Username) of 
        false ->
            AuthResult = agent_auth:auth(Username, Password),
            Respond = handle_login(AuthResult, Username, Password, 
                                   {Endpointtype, Endpointdata, Persistance}, Bandedness),
            Req:respond(Respond);
        {true, _PID} ->
            Req:respond({200, ?CONTENT_JSON, 
                         encode_response(<<"false">>, <<"Agent already logged in.">>)})
    end;

%%--------------------------------------------------------------------
%% @doc
%% Logout an agent from OpenACD.
%%    HTTP request - <server:port>/logout?username=<agent name>
%%                 - <server:port>/logout?agent_pid=<agent pid>
%%        <agent name> - is an agent name.
%%        <agent pid> - is an agent pid.
%%    The method can return:
%%        200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/logout" ++ _Rest, QueryString, Req) ->
    case get_agentpid(QueryString) of
        undefined ->
            Respond = ?RESP_AGENT_NOT_LOGGED;
        Pid ->
            agent:stop(Pid),
            Respond = ?RESP_SUCCESS
    end,
    Req:respond(Respond);

%%--------------------------------------------------------------------
%% @doc
%% Make an agent avaiable for calls.
%%    HTTP request - <server:port>/set_avail?agent=<agent name>
%%                   <server:port>/set_avail?agent_pid=<agent pid>
%%        <agent name> - is an agent name.
%%        <agent pid> - is an agent pid.
%%    The method can return:
%%        200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/set_avail" ++ _Rest, QueryString, Req) ->
    case get_agentpid(QueryString) of 
        undefined ->
            Req:respond(?RESP_AGENT_NOT_LOGGED);
        Pid ->
            agent:set_state(Pid, idle),
            Req:respond(?RESP_SUCCESS)
    end;

%%--------------------------------------------------------------------
%% @doc
%% End current call on agent and put the agent into wrapup state
%%    HTTP request:
%%             <server:port>/hangup?agent=<agent name>
%%             <server:port>/hangup?agent_pid=<agent pid>
%%        <agent name> - is an agent name.
%%        <agent pid> - is an agent pid.
%%    The method can return:
%%        200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/hangup" ++ _Rest, QueryString, Req) ->
    case get_agentpid(QueryString) of 
        undefined ->
            Req:respond(?RESP_AGENT_NOT_LOGGED);
        Pid ->
            %% agent:set_state will not work due to a guard in agent.erl
            #agent{connection=CPid} = agent:dump_state(Pid),
            agent_connection:set_state(CPid, wrapup),
            Req:respond(?RESP_SUCCESS)
    end;

%%--------------------------------------------------------------------
%% @doc
%% Make an agent avaiable for calls after callwork.
%%    HTTP request: 
%%             <server:port>/hangup?agent=<agent name>
%%             <server:port>/hangup?agent_pid=<agent pid>
%%        <agent name> - is an agent name.
%%        <agent pid> - is an agent pid.
%%    The method can return:
%%        200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/end_wrapup" ++ _Rest, QueryString, Req) ->
    case get_agentpid(QueryString) of
        undefined ->
            Req:respond(?RESP_AGENT_NOT_LOGGED);
        Pid ->
            %% agent:set_state will not work due to a guard in agent.erl
            #agent{connection=CPid} = agent:dump_state(Pid),
            agent_connection:set_state(CPid, idle),
            Req:respond(?RESP_SUCCESS)
    end;

%%--------------------------------------------------------------------
%% @doc
%% Returns PID of Agent
%%    HTTP request: 
%%             <server:port>/get_pid?agent=<agent name>
%%        <agent name> - is an agent name.
%%    The method can return:
%%        200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/get_pid" ++ _Rest, QueryString, Req) ->
    AgentName = proplists:get_value("agent", QueryString, ""),
    case agent_manager:query_agent(AgentName) of
        false ->
            Req:respond(?RESP_AGENT_NOT_LOGGED);
        {true, Pid} ->
            Req:respond({200, ?CONTENT_JSON, 
                         encode_response(<<"true">>, [{pid, to_binary(Pid)}])})
    end;

%%--------------------------------------------------------------------
%% @doc
%% Request information about agent's state
%%    HTTP request: 
%%             <server:port>/get_call_state?agent=<agent name>
%%             <server:port>/get_call_state?agent_pid=<agent pid>
%%        <agent name> - is an agent name
%%        <agent pid> - is an agent pid.
%%    The method can return:
%%        200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------    
handle_request("/get_call_state" ++ _Rest, QueryString, Req) ->
    case get_agentpid(QueryString) of 
        undefined ->
            Req:respond(?RESP_AGENT_NOT_LOGGED);
        Pid ->
            #agent{state=State} = agent:dump_state(Pid),
            Req:respond({200, ?CONTENT_JSON, 
                         encode_response(<<"true">>, [{call_state, to_binary(State)}])})
    end;

%%--------------------------------------------------------------------
%% @doc
%% Make an agent unavaiable for calls.
%%    HTTP request:
%%             <server:port>/set_released?agent=<agent name>
%%             <server:port>/set_released?agent_pid=<agent pid>
%%        <agent name> - is an agent name.
%%        <agent pid> - is an agent pid.
%%    The method can return:
%%        200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/set_released" ++ _Rest, QueryString, Req) ->
    case get_agentpid(QueryString) of
        undefined ->
            Req:respond(?RESP_AGENT_NOT_LOGGED);
        Pid ->
            Reason = get_released_reason(QueryString),
            agent:set_state(Pid, released, Reason),
            Req:respond(?RESP_SUCCESS)
    end;

%%--------------------------------------------------------------------
%% @doc
%% Returns Agent's release state.
%%    HTTP request:
%%             <server:port>/get_release_state?agent=<agent name>
%%             <server:port>/get_release_state?agent_pid=<agent pid>
%%        <agent name> - is an agent name.
%%        <agent pid> - is an agent pid.
%%    The method can return:
%%        200 OK - JSON object contains execution result in 'success' field 
%%                 and Released state
%% @end
%%--------------------------------------------------------------------
handle_request("/get_release_state" ++ _Rest, QueryString, Req) ->
    case get_agentpid(QueryString) of
        undefined ->
            Req:respond(?RESP_AGENT_NOT_LOGGED);
        Pid ->
            AgentState = agent:dump_state(Pid),
            case AgentState#agent.statedata of 
                {Id, Label, Bias} ->
                    JSON = encode_response(<<"true">>, 
                                           [
                                            {<<"id">>, to_binary(Id)},
                                            {<<"label">>, to_binary(Label)},
                                            {<<"bias">>, to_binary(Bias)}
                                            ]);
                Others ->
                    JSON = encode_response(<<"true">>, 
                                           [{release_data, to_binary(io_lib:format("~w", [Others]))}])
            end,
            Req:respond({200, ?CONTENT_JSON, JSON})                                        
    end;

%%--------------------------------------------------------------------
%% @doc
%% Returns Agent's release state.
%%    HTTP request:
%%             <server:port>/get_release_opts
%%    The method can return:
%%        200 OK - JSON object contains execution result in 'success' field 
%%                 and Released state
%% @end
%%--------------------------------------------------------------------
handle_request("/get_release_opts" ++ _Rest, _QueryString, Req) ->
    JSON = encode_response(<<"true">>, [ {release_opts, 
                                          lists:map( fun relase_opt_record_to_proplist/1, agent_auth:get_releases())}
                                       ]),
	Req:respond({200, ?CONTENT_JSON, JSON});

%%--------------------------------------------------------------------
%% @doc
%% Executes silent monitoring of Agent's call. 
%%     HTTP request: 
%%              <server:port>/spy?spy=<spy name>&target=<target name>
%%              <server:port>/spy?spy_pid=<spy pid>&target_pid=<target pid>
%%          <spy name> is Spy agent name
%%          <spy pid> is Spy agent pid
%%          <target name> is Target agent name
%%          <target pid> is Target agent pid
%%     The method can return: 
%%          200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/spy" ++ _Rest, QueryString, Req) ->
    SpyPid = get_pid(QueryString, "spy_pid", "spy"),
    TargetPid = get_pid(QueryString, "target_pid", "target"),
    case {SpyPid, TargetPid} of 
        {undefined, undefined} ->
            JSON = encode_response(<<"false">>, <<"Spy and target agents are not logged in.">>);
        {undefined, _} ->
            JSON = encode_response(<<"false">>, <<"Spy agent is not logged in">>);
        {_, undefined} ->
            JSON = encode_response(<<"false">>, <<"Target agent is not logged in">>);
        _Else ->
            #agent{statedata = Callrec} = agent:dump_state(TargetPid),
            %% TODO - The operation could fail because a call is dropped just before.
            %% What we need to do there?
            gen_media:spy(Callrec#call.source, SpyPid, agent:dump_state(SpyPid)),
            JSON = encode_response(<<"true">>)
    end,
    Req:respond({200, ?CONTENT_JSON, JSON});

%%--------------------------------------------------------------------
%% @doc
%% Executes silent monitoring and whisper to Agent.
%%     HTTP request: 
%%              <server:port>/coach?coach=<spy name>&target=<target name>
%%              <server:port>/couch?couch_pid=<spy pid>&target_pid=<target pid>
%%          <spy name> is Spy agent name
%%          <spy pid> is Spy agent pid
%%          <target name> is Target agent name
%%          <target pid> is Target agent pid
%%     The method can return: 
%%          200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/coach" ++ _Rest, QueryString, Req) ->
    CoachPid = get_pid(QueryString, "coach_pid", "coach"),
    TargetPid = get_pid(QueryString, "target_pid", "target"),
    case {CoachPid, TargetPid} of 
        {undefined, undefined} ->
            JSON = encode_response(<<"false">>, <<"Coach and target agents are not logged in.">>);
        {undefined, _} ->
            JSON = encode_response(<<"false">>, <<"Spy agent is not logged in.">>);
        {_, undefined} ->
            JSON = encode_response(<<"false">>, <<"Coach agent is not logged in.">>);
        _Else ->
            #agent{statedata = Callrec} = agent:dump_state(TargetPid),
            CoachRec = agent:dump_state(CoachPid),

            %% Executes freeswitch_media:spy_single_step in separated process 
            %% since spy_single_step will be blocked until Coach agent picks up a spy call.
            spawn(fun() ->
                          freeswitch_media:spy_single_step(Callrec#call.source, CoachRec, agent)
                  end),
            JSON = encode_response(<<"true">>)
    end,
    Req:respond({200, ?CONTENT_JSON, JSON});

%%--------------------------------------------------------------------
%% @doc
%% Transfer a call from an agent to a queue. The agent will be put in wrapup state
%%    HTTP request: 
%%             <server:port>/queue_transfer?agent=<agent name>&queue=<queue name>
%%             <server:port>/queue_transfer?agent_pid=<agent pid>&queue=<queue name>
%%        <agent name> - is an agent name who owns the call
%%        <agent pid> - is an agent pid.
%%        <queue name> - is a queue name where the call will be transfered.
%%    The method can return:
%%        200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------
handle_request("/queue_transfer" ++ _Rest, QueryString, Req) ->
    case get_agentpid(QueryString) of
        undefined ->
            Req:respond(?RESP_AGENT_NOT_LOGGED);
        Pid ->
            QueueName = proplists:get_value("queue", QueryString),
            Result = agent:queue_transfer(Pid, QueueName),
            Req:respond({200, ?CONTENT_JSON, 
                         encode_response(<<"true">>, [
                                                      { return, to_binary(Result) }
                                                      ])})
    end;

%%--------------------------------------------------------------------
%% @doc
%% Transfer a call from one agent to another one.
%%    HTTP request:
%%             <server:port>/agent_transfer?from=<agent name>&to=<target agent>
%%             <server:port>/agent_transfer?from_pid=<agent pid>&to_pid=<target pid>
%%        <agent name> - is an agent name whom
%%        <agent pid> - is an agent pid
%%        <target agent> - is target agent name
%%        <target pid> - is target agent pid
%%    The method can return:
%%        200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------
handle_request("/agent_transfer" ++ _Rest, QueryString, Req) ->
    FromPid = get_pid(QueryString, "from_pid", "from"),
    ToPid = get_pid(QueryString, "to_pid", "to"),
    case {FromPid, ToPid} of 
        {undefined, undefined} ->
            JSON = encode_response(<<"false">>, <<"Transferer and Transferee agents are not logged in.">>);
        {undefined, _} ->
            JSON = encode_response(<<"false">>, <<"Transferer agent is not logged in.">>);
        {_, undefined} ->
            JSON = encode_response(<<"false">>, <<"Transferee agent is not logged in.">>);
        {FromPid, FromPid} ->
            JSON = encode_response(<<"false">>, <<"Transferer and Transferee agents are equal">>);
        _Else ->
            Result = agent:agent_transfer(FromPid, ToPid),
            JSON = encode_response(<<"true">>, [
                                                { return, to_binary(Result) }
                                               ])
    end,
    Req:respond({200, ?CONTENT_JSON, JSON});

%%--------------------------------------------------------------------
%% @doc
%% Put agent's call to hold/unhold state
%%    HTTP request: 
%%             <server:port>/toggle_hold?agent=<agent name>
%%             <server:port>/toggle_hold?agent_pid=<agent pid>
%%        <agent name> - is an agent name
%%        <agent pid> - is agent pid
%%    The method can return:
%%        200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/toggle_hold" ++ _Rest, QueryString, Req) ->
    case get_agentpid(QueryString) of 
        undefined ->
            Req:respond(?RESP_AGENT_NOT_LOGGED);
        Pid ->
            execute_media(Pid, cast, toggle_hold),
            Req:respond(?RESP_SUCCESS)
    end;

%%--------------------------------------------------------------------
%% @doc
%% Dial 3rd party number
%%    HTTP request: 
%%             <server:port>/contact_3rd_party?agent=<agent name>&dest=<3rd party number>
%%             <server:port>/contact_3rd_party?agent_pid=<agent pid>&dest=<3rd party number>
%%        <agent name> - is an agent name
%%        <agent pid> - is agent pid
%%        <3rd party number> - a number to call
%%    The method can return:
%%        200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/contact_3rd_party" ++ _Rest, QueryString, Req) ->
    case get_agentpid(QueryString) of 
        undefined ->
            Req:respond(?RESP_AGENT_NOT_LOGGED);
        Pid ->
            Dest = proplists:get_value("dest", QueryString),
            execute_media(Pid, cast, {contact_3rd_party, Dest}),
            Req:respond(?RESP_SUCCESS)
    end;

%%--------------------------------------------------------------------
%% @doc
%% Merge Agent, Initial and 3rd party calls into conference
%%    HTTP request: 
%%             <server:port>/merge_all?agent=<agent name>
%%             <server:port>/merge_all?agent_pid=<agent pid>
%%        <agent name> - is an agent name
%%        <agent pid> - is agent pid
%%    The method can return:
%%        200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/merge_all" ++ _Rest, QueryString, Req) ->
    case get_agentpid(QueryString) of
        undefined ->
            Req:respond(?RESP_AGENT_NOT_LOGGED);
        Pid ->
            execute_media(Pid, cast, {merge_3rd_party, true}),
            Req:respond(?RESP_SUCCESS)
    end;

%%--------------------------------------------------------------------
%% @doc
%% Ends a conference assotiated with the agent and drops all active calls 
%% within the conference
%%    HTTP request: 
%%             <server:port>/end_conference?agent=<agent name>
%%             <server:port>/end_conference?agent_pid=<agent pid>
%%        <agent name> - is an agent name
%%        <agent pid> - is agent pid
%%    The method can return:
%%        200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/end_conference" ++ _Rest, QueryString, Req) ->
    case get_agentpid(QueryString) of 
        undefined ->
            Req:respond(?RESP_AGENT_NOT_LOGGED);
        Pid ->
            execute_media(Pid, call, end_conference),
            Req:respond(?RESP_SUCCESS)
    end;

handle_request(_Path, _QueryString, Req) ->
    Req:respond({404, [{"Content-Type", "text/html"}], <<"Not Found">>}).

%%%===================================================================
%%% Internal functions
%%%===================================================================
 
%%--------------------------------------------------------------------
%% @doc
%% Checks a authorization result and tries to login an agent into OpenACD
%% @end
%%--------------------------------------------------------------------
handle_login({allow, Id, Skills, Security, Profile}=_AuthResult, 
             Username, Password, {Endpointtype, Endpointdata, Persistance}=Endpoint, 
             Bandedness) ->
    Agent = #agent{
      id = Id, 
      defaultringpath = Bandedness, 
      login = Username, 
      skills = Skills, 
      profile=Profile, 
      password=Password,
      endpointtype = Endpointtype,
      endpointdata = Endpointdata,
      security_level = Security
     },
    {ok, Pid} = agent_connection:start(Agent),
    Node = erlang:node(Pid),
    ?INFO("~s logged in with endpoint ~p", [Username, Endpoint]),
    agent_connection:set_endpoint(Pid, {Endpointtype, Endpointdata}, Persistance),
    AgentPid = agent_connection:get_agentpid(Pid),
    {200, ?CONTENT_JSON, encode_response(<<"true">>, 
                                        [
                                         {node, to_binary(Node)}, 
                                         {pid, to_binary(AgentPid)}
                                       ])};                                                             
handle_login(_AuthResult, _Username, _Password, _Endpoint, _Bandedness) ->
    {200, ?CONTENT_JSON, encode_response(<<"false">>, <<"Invalid username and/or password.">>)}.

%%--------------------------------------------------------------------
%% @doc
%% Extracts AgentPID from HTTP Query string.
%% @end
%%--------------------------------------------------------------------
get_agentpid(QueryString) ->
    get_pid(QueryString, "agent_pid", "agent").

%%--------------------------------------------------------------------
%% @doc
%% Extracts PID from Query string. If 'pid' parameter is not defined 
%% when 'agent' will be used to get Agent PID registered in agent_manager
%% @end
%%--------------------------------------------------------------------
get_pid(QueryString, Pid, Name) ->
    case proplists:get_value(Pid, QueryString) of 
        undefined ->
            get_pid(Name, QueryString);
        Value ->
            %% erlang:is_process_alive will not work with remote nodes
            %% So we need another way to check Pid validity
            to_pid(Value)
    end.
get_pid(Name, QueryString) ->
    Value = proplists:get_value(Name, QueryString, ""),
    case agent_manager:query_agent(Value) of
        false ->
            undefined;
        {true, Pid} ->
            Pid
    end.

%%--------------------------------------------------------------------
%% @doc
%% Extract and format Release reason
%% @end
%%--------------------------------------------------------------------
get_released_reason(QueryString) ->
    Id = proplists:get_value("id", QueryString),
    Label = proplists:get_value("label", QueryString),
    Bias = proplists:get_value("bias", QueryString),
    get_released_reason(Id, Label, Bias).

get_released_reason(undefined, _, _) ->
    default;
get_released_reason(_, undefined, _) ->
    default;
get_released_reason(_, _, undefined) ->
    default;
get_released_reason(Id, Label, Bias) ->
    {Id, Label, list_to_integer(Bias)}.

%%--------------------------------------------------------------------
%% @doc
%% Encode responce in JSON format
%% @end
%%--------------------------------------------------------------------
encode_response(Result) ->
    mochijson2:encode([{success, Result}]).

encode_response(Result, Message) when is_binary(Message) ->
    mochijson2:encode([{success, Result}, {message, Message}]);
encode_response(Result, Rest) when is_list(Rest) ->
    mochijson2:encode([{success, Result} | Rest]).

% Utility functions for converting a #release_opt record (located in agent.hrl) into a property list. 
% These functions are used to convert a list of #release_opt's into a JSON string.
relase_opt_record_to_proplist(#release_opt{} = Rec) ->
  lists:zip(record_info(fields, release_opt), lists:map(fun to_binary/1, tl(tuple_to_list(Rec)))).

%%--------------------------------------------------------------------
%% @doc
%% Execute a command on gen_media/freeswitch_media process. Type defines a call type: call or cast
%% @end
%%--------------------------------------------------------------------
execute_media(#call{source=Pid}=Call, call, Cmd) when is_record(Call, call) ->
    gen_media:call(Pid, Cmd);
execute_media(#call{source=Pid}=Call, cast, Cmd) when is_record(Call, call) ->
    gen_media:cast(Pid, Cmd);
execute_media(Pid, Type, Cmd) when is_pid(Pid) ->
    #agent{statedata=Call} = agent:dump_state(Pid),
    execute_media(Call, Type, Cmd).
%%--------------------------------------------------------------------
%% @doc
%% Convert terms into binary format. 
%% List, Atom, Pid, Integer and Binary are supported for now
%% @end
%%--------------------------------------------------------------------
to_binary(Var) when is_list(Var) ->
    list_to_binary(Var);
to_binary(Var) when is_atom(Var) ->
    atom_to_binary(Var, latin1);
to_binary(Var) when is_pid(Var) ->
    list_to_binary(pid_to_list(Var));
to_binary(Var) when is_binary(Var) ->
    Var;
to_binary(Var) when is_integer(Var) ->
    list_to_binary(integer_to_list(Var)).

%%--------------------------------------------------------------------
%% @doc
%% Convert List or Binary to Pid
%% @end
%%--------------------------------------------------------------------
to_pid(Var) when is_binary(Var) ->
    list_to_pid(binary_to_list(Var));
to_pid(Var) when is_list(Var) ->
    list_to_pid(Var);
to_pid(Var) when is_pid(Var) ->
    Var.

%%--------------------------------------------------------------------
%% @doc
%% Returns open_rcc application path where it has been started. 
%% Overwise it returns current folder.
%% @end
%%--------------------------------------------------------------------
get_app_dir() ->
    case code:lib_dir(open_rcc) of 
        {error, _} ->
            "./";
        Dir ->
            Dir
    end.

%%--------------------------------------------------------------------
%% @doc
%% Returns SSL certificated defined either in appication config or 
%% self-signed ceritifcate created by buildcert.sh
%% @end
%%--------------------------------------------------------------------
get_certfile() ->
    case application:get_env(open_rcc, certfile) of 
        undefined ->
            {ok, Hostname} = inet:gethostname(),
            filename:join(get_app_dir(), io_lib:format("~s.self.crt", [Hostname]));
        {ok, Cert} ->
            Cert
    end.

%%--------------------------------------------------------------------
%% @doc
%% Returns SSL key defined either in appication config or 
%% self-key created by buildcert.sh
%% @end
%%--------------------------------------------------------------------
get_keyfile() ->
    case application:get_env(open_rcc, keyfile) of
        undefined ->
            {ok, Hostname} = inet:gethostname(),
            filename:join(get_app_dir(), io_lib:format("~s.self.key", [Hostname]));
        {ok, Key} ->
            Key
    end.
