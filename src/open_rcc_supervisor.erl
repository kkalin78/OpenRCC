-module(open_rcc_supervisor).

-behaviour(supervisor).

-export([start_link/0]).
-export([init/1]).

start_link() ->
    supervisor:start_link(open_rcc_supervisor, []).

init(_Args) ->
    % TODO - Make Port configureable
    {ok, {{one_for_one, 1, 60},
          [{open_rcc, {open_rcc_server, start_link, [8383]},
            permanent, brutal_kill, worker, [open_rcc]}]}}.
