open Async
open Cohttp
open Cohttp_async

open Jg_types

type client = {
    client_id: string;
    client_secret: string;
    redirect_uris: string list;
    scope: string list;
    logo_uri: string option;
    client_name: string option;
};;

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
}] |> Core.List.map ~f:(fun x -> (x.client_id, x)) |> Core.String.Map.of_alist_exn;;

let authServer = Yojson.Basic.from_file "authserver.json";;

let rec yojson_to_jingoo (x : Yojson.Basic.json) = match x with
    | `String x -> Jg_types.Tstr x
    | `Int x -> Jg_types.Tint x
    | `Bool x -> Jg_types.Tbool x
    | `Float x -> Jg_types.Tfloat x
    | `List x -> Jg_types.Tlist (List.map yojson_to_jingoo x)
    | `Null-> Jg_types.Tnull
    | `Assoc x -> Jg_types.Tobj (
            Base.List.map
                ~f:(fun (k, v) -> (k, yojson_to_jingoo v))
                x
    );;


let client_to_jingoo (x : client) = Jg_types.Tobj [
    ("client_id", (Jg_types.Tstr x.client_id));
    ("client_secret", (Jg_types.Tstr x.client_secret));
    ("scope", (Jg_types.Tstr (Core.String.concat ~sep:" " x.scope)));
    ("redirect_uris", (Jg_types.Tlist (List.map (fun x -> Jg_types.Tstr x) x.redirect_uris)));
    ("logo_uri", match x.logo_uri with Some x -> Jg_types.Tstr x | None -> Jg_types.Tnull);
    ("client_name", match x.client_name with Some x -> Jg_types.Tstr x | None -> Jg_types.Tnull)
];;

let default_response req body = 
    let uri = req |> Request.uri |> Uri.to_string in
    let meth = req |> Request.meth |> Code.string_of_method in
    let headers = req |> Request.headers |> Header.to_string in
    (body |> Cohttp_async.Body.to_string >>= (
        fun body -> Cohttp_async.Server.respond_string ~status:`OK (Printf.sprintf "Uri: %s\nMethod: %s\nHeaders\nHeaders: %s\nBody: %s" uri meth headers body) 
    ))
;;


let requests = Core.Hashtbl.create (module Core.String) ();;
let codes = Core.Hashtbl.create (module Core.String) ();;
(* Calling this nosql for now for consistency with the book *)
let nosql = Core.Hashtbl.create (module Core.String) ();;

let index _ _ =
    Server.respond_string ~status:`OK (
        Jg_template.from_file "files/authorizationServer/index.html" ~models:[
            ("clients", Jg_types.Tlist (Core.String.Map.to_alist clients |> List.map (fun (_, x) -> client_to_jingoo x)));
            ("authServer", yojson_to_jingoo authServer)
        ]);;


let authorize req _body = 
    let open Core in
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
    let reqid = Core.Uuid.create () |> Core.Uuid.to_string in
    let () = Hashtbl.set requests ~key:reqid ~data:(`Code, client, redirect_uri |> Uri.of_string, state) in
    Server.respond_string ~status:`OK (Jg_template.from_file "files/authorizationServer/approve.html"
        ~models:[
            ("client", client_to_jingoo client);
            ("scope", Jg_types.Tlist (List.map ~f:(fun x -> Jg_types.Tstr x) rscope));
            ("reqid", Jg_types.Tstr reqid)
        ]
    );;



let approve _req body =
    let open Core in
    Cohttp_async.Body.to_string body >>=
    (fun body ->
        String.split ~on:'&' body |>
        List.map ~f:(String.split ~on:'=') |>
        List.map ~f:(function [x;y] -> (x,y) | _ -> assert false) |>
        String.Map.of_alist_exn |>
        String.Map.find |> 
    (fun param -> (
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
    ))));;

let token req body =
    let open Core in
    Cohttp_async.Body.to_string body >>=
    (fun body ->
        String.split ~on:'&' body |>
        List.map ~f:(String.split ~on:'=') |>
        List.map ~f:(function [x;y] -> (x,y) | _ -> assert false) |>
        String.Map.of_alist_exn |>
        String.Map.find_exn |> 
    (fun param -> (
    let grant_type = param "grant_type" in (* |> Option.value_exn in (* authorization_code *) *)
    let code_str = param "code" in
    let code = Hashtbl.find_exn codes code_str in
    let () = Hashtbl.remove codes code_str in
    let redirect_uri = param "redirect_uri" in
    let authorization_header = (Request.headers req |> Header.get) "Authorization" |> Option.value_exn
    in
    let (client_id, client_secret) = match String.split ~on:' ' authorization_header with
        ["Basic"; clientCredentials] -> (B64.decode clientCredentials |> String.split ~on:':' |> function [x;y]->(x,y)|_->assert false)
        | _ -> assert false
    in
    let client = String.Map.find_exn clients client_id   in
    let () = assert (client.client_secret = client_secret) in
    let () = assert (grant_type = "authorization_code")   in
    let access_token = Uuid.create () |> Uuid.to_string  in
    let () = Hashtbl.set nosql ~key:access_token ~data:(client, code.code_scope)
    in
    Server.respond_string ~status:`OK (`Assoc [
        ("access_token", `String access_token);
        ("token_type", `String "Bearer");
        ("scope", `String (String.concat ~sep:" " code.code_scope))
    ] |> Yojson.Basic.to_string))))
;;

let callback ~body _conn req =
    let path = req |> Request.uri |> Uri.path in
    let meth = req |> Request.meth in
    match path, meth with
    | "/", `GET -> index req body 
(*    | "/authorize", `GET -> Server.respond_string ~status:`OK ~body:"LOL" () *)
    | "/authorize", `GET -> authorize req body 
    | "/approve", `POST -> approve req body
    | "/token", `POST -> token req body
    | _, _ -> default_response req body

;;

let server =
  Server.create ~on_handler_error:`Raise (Async_extra.Tcp.Where_to_listen.of_port 9001) (callback)

let () =
  Core.never_returns (Scheduler.go ())
