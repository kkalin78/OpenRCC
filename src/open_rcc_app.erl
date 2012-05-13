-module(open_rcc_app).
-behaviour(application).

-include_lib("OpenACD/include/log.hrl").

-export([start/2, stop/1]).

start(_Type, _Args) ->
    ?INFO("Starting OpenRCC application", []),
    open_rcc_supervisor:start_link().

stop(_State) ->
    ok.
