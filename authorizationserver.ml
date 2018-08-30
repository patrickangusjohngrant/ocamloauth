(* 
* Reimplementing this guy as a means of learning oauth:
* 
* https://github.com/oauthinaction/oauth-in-action-code/blob/master/example/authorizationServer.js
*)

open Async
open Core
open Cohttp
open Cohttp_async

type client = {
    client_id: string;
    client_secret: string;
    redirect_uris: string list;
    scope: string list;
    logo_uri: string option;
    client_name: string option;
};;

(* Should this and the previous type be amalgamated? *)
type resource = {
	resource_id: string;
	resource_secret: string;
};;

let protectedResources = [{
	resource_id="protected-resource-1";
    resource_secret="protected-resource-secret-1"
}] |> List.map ~f:(fun x -> (x.resource_id, x)) |> String.Map.of_alist_exn;;


type code = {
    code_scope: string list;
    code_client: client;
};;


let clients = [{
	client_id= "oauth-client-1";
    client_secret= "oauth-client-secret-1";
	redirect_uris= ["http://localhost:9000/callback"];
    scope= [ "foo"; "bar" ];
	logo_uri= Some "https://images.manning.com/720/960/resize/book/e/14336f9-6493-46dc-938c-11a34c9d20ac/Richer-OAuth2-HI.png";
    client_name= Some "OAuth in Action Exercise Client"
};
{
    client_id= "oauth-client-2";
	client_secret= "oauth-client-secret-1";
	redirect_uris= ["http://localhost:9000/callback"];
    logo_uri= None;
	scope= ["bar"];
    client_name= None
};
{
    client_id= "native-client-1";
	client_secret= "oauth-native-secret-1";
	redirect_uris= ["mynativeapp://"];
	scope= ["openid"; "profile"; "email"; "phone"; "address"];
    logo_uri= None;
    client_name= None
}] |> List.map ~f:(fun x -> (x.client_id, x)) |> String.Map.of_alist_exn;;

(* TODO: remove this? *)
let authServer = Yojson.Basic.from_file "authserver.json";;

(* TODO: ditto? *)
let rec yojson_to_jingoo (x : Yojson.Basic.json) = 
	let open Jg_types in 
	match x with
    | `String x -> Tstr x
    | `Int x -> Tint x
    | `Bool x -> Tbool x
    | `Float x -> Tfloat x
    | `List x -> Tlist (List.map ~f:yojson_to_jingoo x)
    | `Null-> Tnull
    | `Assoc x -> Tobj (List.map ~f:(fun (k, v) -> (k, yojson_to_jingoo v)) x);;


let client_to_jingoo (x : client) = 
	let open Jg_types in 
	Tobj [
        ("client_id", 		(Tstr x.client_id));
        ("client_secret", 	(Tstr x.client_secret));
        ("scope", 			(Tstr (String.concat ~sep:" " x.scope)));
        ("redirect_uris", 	(Tlist (List.map ~f:(fun x -> Jg_types.Tstr x) x.redirect_uris)));
        ("logo_uri", 	match x.logo_uri with Some x -> Tstr x | None -> Jg_types.Tnull);
        ("client_name", match x.client_name with Some x -> Tstr x | None -> Jg_types.Tnull)
	];;

let default_response req body = 
    let uri = req |> Request.uri |> Uri.to_string in
    let meth = req |> Request.meth |> Code.string_of_method in
    let headers = req |> Request.headers |> Header.to_string in
    Cohttp_async.Server.respond_string ~status:`OK (Printf.sprintf "Uri: %s\nMethod: %s\nHeaders\nHeaders: %s\nBody: %s" uri meth headers body) 
;;


let requests = Hashtbl.create (module String) ();;
let codes = Hashtbl.create (module String) ();;
(* Calling this nosql for now for consistency with the book *)
let nosql = Hashtbl.create (module String) ();;

let index _ _ =
    Server.respond_string ~status:`OK (
        Jg_template.from_file "files/authorizationServer/index.html" ~models:[
            ("clients", Jg_types.Tlist (String.Map.to_alist clients |> List.map ~f:(fun (_, x) -> client_to_jingoo x)));
            ("authServer", yojson_to_jingoo authServer)
        ]);;


let authorize req _body = 
    let uri_param = Uri.get_query_param (Request.uri req)                                   in
    let rscope = uri_param "scope" |> Option.value_exn |> String.split ~on:' '              in
    let client_id = match uri_param "client_id" with Some x -> x | None -> assert false     in
    let client = String.Map.find_exn clients client_id                                      in
    let redirect_uri = match uri_param "redirect_uri" with Some x -> x | None -> assert false in
    let () = assert (List.mem client.redirect_uris redirect_uri ~equal:(=)) in
    let state = uri_param "state" |> Option.value_exn in
    let () = assert (
        List.for_all rscope ~f:(fun x -> List.mem client.scope x ~equal:(=))
    )
    in
    let reqid = Uuid.create () |> Uuid.to_string in
    let () = Hashtbl.set requests ~key:reqid ~data:(`Code, client, redirect_uri |> Uri.of_string, state) in
    Server.respond_string ~status:`OK (Jg_template.from_file "files/authorizationServer/approve.html"
        ~models:[
            ("client", client_to_jingoo client);
            ("scope", Jg_types.Tlist (List.map ~f:(fun x -> Jg_types.Tstr x) rscope));
            ("reqid", Jg_types.Tstr reqid)
        ]
    );;

let param_from_body (body:string) (key:string) =
	(String.split ~on:'&' body |>
    List.map ~f:(String.split ~on:'=') |>
    List.map ~f:(function [x;y] -> (x,y) | _ -> assert false) |>
    String.Map.of_alist_exn |>
    String.Map.find) key;;

let param_from_body_exn body key =
	match param_from_body body key with
	| Some x -> x
	| None -> assert false;;

let approve _req body =
	let param = param_from_body body
	in
    let reqid = param "reqid" |> Option.value_exn in
    let `Code, client, redirect_uri, state = Hashtbl.find_exn requests reqid (* TODO: `Code or `Token *) in
    let () = Hashtbl.remove requests reqid in
    let _approve = param "approve" in
    let scopes = List.filter client.scope ~f:(fun x -> param ("scope_"^x) = Some "on")
    in
	let code = Uuid.create () |> Uuid.to_string in
    let () = Hashtbl.set codes ~key:code ~data:{
        code_scope=scopes;
        code_client=client;
        (* user: user; *)
        (* code_request=None *)
    }
    in
    Cohttp_async.Server.respond_with_redirect (
        Uri.with_query' redirect_uri [("code", code); ("state", state)] 
    );;

let parse_http_basic req =
	let authorization_header = (Request.headers req |> Header.get) "Authorization" |> Option.value_exn
	in
    let u_p = match String.split ~on:' ' authorization_header with
        ["Basic"; clientCredentials] -> (
			B64.decode clientCredentials |> String.split ~on:':'
		)
        | _ -> assert false
	in
	match u_p with
	| [username; password] -> (username, password)
	| _ -> assert false;;

let token req body =
    (let param = param_from_body_exn body                  in
    let grant_type = param "grant_type"                    in 
    let code_str = param "code"                            in
    let code = Hashtbl.find_exn codes code_str             in
    let () = Hashtbl.remove codes code_str                 in
    let redirect_uri = param "redirect_uri"                in
    let client_id, client_secret = parse_http_basic req    in
    let client = String.Map.find_exn clients client_id     in
    let () = assert (client.client_secret = client_secret) in
    let () = assert (grant_type = "authorization_code")    in
    let access_token = Uuid.create () |> Uuid.to_string    in
    let () = Hashtbl.set nosql ~key:access_token ~data:(client, code.code_scope)
    in
    Server.respond_string ~status:`OK (`Assoc [
        ("access_token", `String access_token);
        ("token_type", `String "Bearer");
        ("scope", `String (String.concat ~sep:" " code.code_scope))
    ] |> Yojson.Basic.to_string))
;;

(* 


app.post('/introspect', function(req, res) {
        var auth = req.headers['authorization'];
        var resourceCredentials = new Buffer(auth.slice('basic '.length), 'base64').toString().split(':');
        var resourceId = querystring.unescape(resourceCredentials[0]);
        var resourceSecret = querystring.unescape(resourceCredentials[1]);

        var resource = getProtectedResource(resourceId);
        if (!resource) {
                console.log('Unknown resource %s', resourceId);
                res.status(401).end();
                return;
        }

        if (resource.resource_secret != resourceSecret) {
                console.log('Mismatched secret, expected %s got %s', resource.resource_secret, resourceSecret);
                res.status(401).end();
                return;
        }

        var inToken = req.body.token;
        console.log('Introspecting token %s', inToken);
        nosql.one(function(token) {
                if (token.access_token == inToken) {
                        return token;
                }
        }, function(err, token) {
                if (token) {
                        console.log("We found a matching token: %s", inToken);

                        var introspectionResponse = {};
                        introspectionResponse.active = true;
                        introspectionResponse.iss = 'http://localhost:9001/';
                        introspectionResponse.sub = token.user;
                        introspectionResponse.scope = token.scope.join(' ');
                        introspectionResponse.client_id = token.client_id;

                        res.status(200).json(introspectionResponse);
                        return;
                } else {
                        console.log('No matching token was found.');

                        var introspectionResponse = {};
                        introspectionResponse.active = false;
                        res.status(200).json(introspectionResponse);
                        return;
                }
        });


});

*)

let introspect req body = 
    let resource_id, resource_secret = parse_http_basic req in
    let resource = String.Map.find_exn protectedResources resource_id in
	let () = assert (resource_secret = resource.resource_secret)
	in
	let param = param_from_body_exn body in
	let token = param "token" in
	let client, scope = Hashtbl.find_exn nosql token
	in
	Server.respond_string ~status:`OK
		(`Assoc [
			("active", `Bool true);
			("iss", `String "http://localhost:9001/");
			("sub", `String "wtf"); (* eh *)
			("scope", `String (String.concat ~sep:" " scope));
			("client_id", `String client.client_id);
    	] |> Yojson.Basic.to_string);;


let callback ~body _conn req =
    Cohttp_async.Body.to_string body >>= (
	fun body -> (
    let path = req |> Request.uri |> Uri.path in
    let meth = req |> Request.meth in
    match path, meth with
    | "/", `GET -> index req body 
    | "/authorize", `GET -> authorize req body 
    | "/approve", `POST -> approve req body
    | "/token", `POST -> token req body
    | "/introspect", `POST -> introspect req body
    | _, _ -> default_response req body
	))

;;

let server =
  Server.create ~on_handler_error:`Raise (Async_extra.Tcp.Where_to_listen.of_port 9001) (callback)

let () = never_returns (Scheduler.go ())
