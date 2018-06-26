%%%----------------------------------------------------------------------
%%% File    : mod_lhc.erl
%%% Author  : Remigijus Kiminas <remdex@gmail.com>
%%% Purpose : Notyfy LHC about connected and unconnected operators
%%% Created : 3 May 2012 by Remigijus Kiminas <remdex@gmail.com>>
%%%
%%%
%%% ejabberd, Copyright (C) 2015   Live Helper Chat
%%%
%%% This program is free software; you can redistribute it and/or
%%% modify it under the terms of the GNU General Public License as
%%% published by the Free Software Foundation; either version 2 of the
%%% License, or (at your option) any later version.
%%%
%%% This program is distributed in the hope that it will be useful,
%%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
%%% General Public License for more details.
%%%
%%% You should have received a copy of the GNU General Public License along
%%% with this program; if not, write to the Free Software Foundation, Inc.,
%%% 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
%%%
%%%----------------------------------------------------------------------

-module(mod_lhc).

-behavior(gen_mod).
-include("ejabberd.hrl").
-include("logger.hrl").
-include("ejabberd_http.hrl").
-include("xmpp.hrl").

-export([start/2, stop/1, on_set/4, on_unset/4,on_filter_packet/1,create_message/3,process/2]).
-export([mod_opt_type/1, depends/2]).

-spec depends(binary(), gen_mod:opts()) -> [{module(), hard | soft}].

depends(_Host, _Opts) ->
    [].
	
mod_opt_type(message_address) ->
	fun(<<"http://", _/binary>> = URL) -> URL;
		(<<"https://", _/binary>> = URL) -> URL
	end;
mod_opt_type(login_address) ->
	fun(<<"http://", _/binary>> = URL) -> URL;
		(<<"https://", _/binary>> = URL) -> URL
	end;
mod_opt_type(logout_address) ->
	fun(<<"http://", _/binary>> = URL) -> URL;
		(<<"https://", _/binary>> = URL) -> URL
	end;
mod_opt_type(basedomain) ->
    fun iolist_to_binary/1;	
mod_opt_type(ahprotocol) ->
    fun iolist_to_binary/1;	
mod_opt_type(ahenviroment) ->
    fun iolist_to_binary/1;		
	
mod_opt_type(_) ->
    [message_address, basedomain, ahprotocol, ahenviroment, login_address, logout_address].
	
start(Host, _Opts) ->
   ejabberd_hooks:add(set_presence_hook, Host, ?MODULE, on_set, 50),
   ejabberd_hooks:add(unset_presence_hook, Host, ?MODULE, on_unset, 50),
   ejabberd_hooks:add(filter_packet, global, ?MODULE, on_filter_packet, 50),
   ok.

   
stop(Host) ->
   ejabberd_hooks:delete(set_presence_hook, Host, ?MODULE, on_set, 50),
   ejabberd_hooks:delete(unset_presence_hook, Host, ?MODULE, on_unset, 50),
   ejabberd_hooks:delete(filter_packet, global, ?MODULE, on_filter_packet, 50),
   ok.
			 
create_message(_From, _To, _Packet) ->
   stop.
   
on_filter_packet(#message{from = From, to = To, id = ID, type = Type, body=XML} = Msg) ->
	?INFO_MSG("Need222 store body ~p ~p ~p ~p ~p",[From,To,ID,Type,XML]),
	
	#jid{luser = LUser, lserver = LServer} = From,
    
    %% We send to LHC only request from operators, like visitors in all cases are using web interface
    case re:run(LUser,"^visitor\.[0-9](.*?)") of
	  {match, _} -> ok;
	  nomatch -> 
		Body = xmpp:get_text(XML),
		?INFO_MSG("Need33333 store body ~p ~p ~p",[Body,Type,LServer,LUser]),
	    %% Send only chat type with non empty body
	    %% In the future possible to extend and send typing status here just parse XML
		
		#jid{luser = LUser1, lserver = _LReceiverServer} = To,
		LReceiverUser = jlib:nodeprep(LUser1),
		?INFO_MSG("Need55555 store body ~p",[LReceiverUser]),
		if (Type == chat) and (Body /= false) -> 
			Method = post,
			URL = gen_mod:get_module_opt(LServer, ?MODULE, message_address,
													fun iolist_to_binary/1,
													undefined),	
													
			BaseDomain = gen_mod:get_module_opt(LServer, ?MODULE, basedomain,
													fun iolist_to_binary/1,
													undefined),
													
			AHProtocol = gen_mod:get_module_opt(LServer, ?MODULE, ahprotocol,
													fun iolist_to_binary/1,
													undefined),
		   
			AHEnviroment = gen_mod:get_module_opt(LServer, ?MODULE, ahenviroment,
								fun(B) when is_boolean(B) -> B end, 
								false),
													
															 
			Header = [],
			TypeMessage = "application/x-www-form-urlencoded",
			BodyMessage = "body="++erlang:binary_to_list(ejabberd_http:url_encode(Body))++
			"&sender="++erlang:binary_to_list(ejabberd_http:url_encode(LUser))++
			"&receiver="++erlang:binary_to_list(ejabberd_http:url_encode(LReceiverUser))++
			"&server="++erlang:binary_to_list(ejabberd_http:url_encode(LServer)),
			HTTPOptions = [],
			Options = [],
			 
			case AHEnviroment of
				true -> 
				   [UserJID|_] = string:tokens(erlang:binary_to_list(LUser),"@"), 
				   httpc:request(Method, {erlang:binary_to_list(AHProtocol)++ re:replace(lists:last(string:tokens(UserJID,".")),"-",".",[{return,list}]) ++ "." ++ erlang:binary_to_list(BaseDomain) ++ "/xmppservice/processmessage", Header, TypeMessage, BodyMessage}, HTTPOptions, Options);     
				false -> 
				   httpc:request(Method, {erlang:binary_to_list(URL), Header, TypeMessage, BodyMessage}, HTTPOptions, Options)
			end;	
		true ->
		    false
	    end		
		%% ?INFO_MSG("Need store body",[BodyMessage,LUser]);
	end,
	
	Msg.
	
on_set(User, Server, _Resource, _Packet) ->
   LUser = jlib:nodeprep(User),
   LServer = jlib:nodeprep(Server),
   %%_SID = ejabberd_sm:get_session_pid(LUser, LServer, Resource),
   ?INFO_MSG("Packet11 From intercepted ~p ~p", [LUser, LServer]),
   %% Inform about new connection only if operator is connected
   case re:run(erlang:binary_to_list(LUser),"^visitor\.[0-9](.*?)") of
	  {match, _} ->  ok;
	  nomatch -> 
		   Method = post,
		   URL = gen_mod:get_module_opt(LServer, ?MODULE, login_address,
		                                            fun iolist_to_binary/1,
		                                            undefined),
		   BaseDomain = gen_mod:get_module_opt(LServer, ?MODULE, basedomain,
		                                            fun iolist_to_binary/1,
		                                            undefined),
		                                            
	       AHProtocol = gen_mod:get_module_opt(LServer, ?MODULE, ahprotocol,
		                                            fun iolist_to_binary/1,
		                                            undefined),
													
		   AHEnviroment = gen_mod:get_module_opt(LServer, ?MODULE, ahenviroment,
                                fun(B) when is_boolean(B) -> B end, 
                                false),										
		   ?INFO_MSG("Packet22 From intercepted ~p ~p", [URL,AHEnviroment]),                                      
			
		   Header = [],
		   Type = "application/json",
		   Body = "{\"action\":\"connect\",\"user\":\""++erlang:binary_to_list(LUser)++"\",\"server\":\""++erlang:binary_to_list(LServer)++"\"}",   
		   HTTPOptions = [],
		   Options = [],
		   ?INFO_MSG("Packet33 From intercepted ~p", [Body]), 
		   
		   case AHEnviroment of
			    true -> 
			       [UserJID|_] = string:tokens(erlang:binary_to_list(LUser),"@"), 
				   ?INFO_MSG("PacketTrue From intercepted ~p", [AHEnviroment]), 
			       httpc:request(Method, {erlang:binary_to_list(AHProtocol)++ re:replace(lists:last(string:tokens(UserJID,".")),"-",".",[{return,list}]) ++ "." ++ erlang:binary_to_list(BaseDomain) ++ "/xmppservice/operatorstatus", Header, Type, Body}, HTTPOptions, Options);      
			       %% ?INFO_MSG("Automated hosting enviroment",["Automated"]);
			    false -> 
				   ?INFO_MSG("PacketFalse From intercepted ~p", [AHEnviroment]), 
				   case httpc:request(Method, {erlang:binary_to_list(URL), Header, Type, Body}, HTTPOptions, Options) of   
						{ok, {_,_,Body}}-> Body;  
						{error, Reason}->io:format("error cause ~p~n",[Reason])  
				   end
		   end
		  
   end.
          
   %%?INFO_MSG("Presence set demo compile Request was send %p",[Body]).

on_unset(User, Server, _Resource, _Packet) ->
   LUser = jlib:nodeprep(User),
   LServer = jlib:nodeprep(Server),
       
   %% Inform about closed connection only if operator is disconnected
   case re:run(erlang:binary_to_list(LUser),"^visitor\.[0-9](.*?)") of
	  {match, _} ->  ok;
   nomatch -> 
	   Method = post, 
	   URL = gen_mod:get_module_opt(LServer, ?MODULE, logout_address,
	                                            fun iolist_to_binary/1,
	                                            undefined),
	                                            
	   BaseDomain = gen_mod:get_module_opt(LServer, ?MODULE, basedomain,
		                                            fun iolist_to_binary/1,
		                                            undefined),
		                                            
	   AHProtocol = gen_mod:get_module_opt(LServer, ?MODULE, ahprotocol,
		                                            fun iolist_to_binary/1,
		                                            undefined),
		   
	   AHEnviroment = gen_mod:get_module_opt(LServer, ?MODULE, ahenviroment,
                                fun(B) when is_boolean(B) -> B end, 
                                false),
	   Header = [],
	   Type = "application/json",
	   Body = "{\"action\":\"disconnect\",\"user\":\""++erlang:binary_to_list(LUser)++"\",\"server\":\""++erlang:binary_to_list(LServer)++"\"}",   
	   HTTPOptions = [],
	   Options = [],
	   
	   case AHEnviroment of
			    true -> 
			       [UserJID|_] = string:tokens(erlang:binary_to_list(LUser),"@"), 
			       httpc:request(Method, {erlang:binary_to_list(AHProtocol)++ re:replace(lists:last(string:tokens(UserJID,".")),"-",".",[{return,list}]) ++ "." ++ erlang:binary_to_list(BaseDomain) ++ "/xmppservice/operatorstatus", Header, Type, Body}, HTTPOptions, Options);      
			       %% ?INFO_MSG("Automated hosting enviroment",["Automated"]);
			    false -> 
			       httpc:request(Method, {erlang:binary_to_list(URL), Header, Type, Body}, HTTPOptions, Options)
	   end	   
   end.
    
  %% process any request to "/sockets"
	process([<<"makeonline">>], _Request) ->
		
	    % FIXME: implementation goes here
	    "Not implemented yet";
	
	%% process all remaining requests
	process(_Page, _Request) ->
	    % FIXME: implementation goes here	
	    "Fallback result".
      
    
   %%?INFO_MSG("Presence set demo un-set %p %p", [erlang:binary_to_list(LUser),erlang:binary_to_list(LServer)]).