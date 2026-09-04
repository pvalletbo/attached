use attached_session_sync_protocol::{
    account::{AccountId, ApiKeyScope, ApiToken, RecordId},
    api::{
        ACCOUNTS_PATH, ALLOW_ACCOUNTS, ALLOW_CURSORLESS_RECORDS, ALLOW_HEALTH, ALLOW_RECORD_INDEX,
        AUTHENTICATE_VALUE, CACHE_CONTROL_VALUE, CreateAccountResponse, Envelope, ErrorCode,
        ErrorDto, HEALTH_PATH, STATUS_BAD_REQUEST, STATUS_CREATED, STATUS_METHOD_NOT_ALLOWED,
        STATUS_NO_CONTENT, STATUS_NOT_FOUND, STATUS_OK, STATUS_PAYLOAD_TOO_LARGE,
        STATUS_TOO_MANY_REQUESTS, STATUS_UNAUTHORIZED, STATUS_UNAVAILABLE,
    },
    limits::MAX_API_BODY_BYTES,
};
use futures_util::StreamExt as _;
use worker::{Env, Headers, Method, Request, RequestInit, Response, RouteContext, Router, State};

use crate::{
    issuance,
    model::{ENCODED_ACCOUNT_BYTES, MutationError, MutationOutcome, StoredAccount},
    storage::{self, InitializeOutcome, StoreError},
};

const ACCOUNT_OBJECT_BINDING: &str = "ACCOUNTS";
const ACCOUNT_RECORD_INDEX_ROUTE: &str = "/v1/accounts/:account_id/records";
const ACCOUNT_RECORD_ROUTE: &str = "/v1/accounts/:account_id/records/:record_id";
const ROUTER_FALLBACK_ROUTE: &str = "/*path";
const INTERNAL_INITIALIZE_PATH: &str = "/__attached/initialize-account/v1";
const INTERNAL_ORIGIN: &str = "https://account-object.internal";
const INTERNAL_OVERSIZED_BODY_HEADER: &str = "x-attached-internal-oversized-body";
const MAX_ACCOUNT_ISSUANCE_ATTEMPTS: usize = 4;

const STATUS_CONFLICT: u16 = 409;

pub(crate) async fn handle_public_request(request: Request, env: &Env) -> worker::Result<Response> {
    public_router().run(request, env.clone()).await
}

fn public_router() -> Router<'static, ()> {
    // Register complete resources rather than method-specific routes so the
    // handlers can preserve the protocol's JSON errors and route-specific
    // Allow headers instead of worker::Router's plain-text 405 response.
    Router::new()
        .on(HEALTH_PATH, handle_health)
        .on_async(ACCOUNTS_PATH, handle_accounts)
        .on_async(ACCOUNT_RECORD_INDEX_ROUTE, route_public_account_request)
        .on_async(ACCOUNT_RECORD_ROUTE, route_public_account_request)
        .or_else_any_method("/", route_not_found)
        .or_else_any_method(ROUTER_FALLBACK_ROUTE, route_not_found)
}

async fn route_public_account_request(
    request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    if context
        .param("account_id")
        .is_none_or(|value| value.is_empty())
    {
        return error_response(STATUS_NOT_FOUND, ErrorCode::InvalidRequest);
    }
    let record_route = context.param("record_id").is_some();
    let allowed = if record_route {
        matches!(request.method(), Method::Get | Method::Put)
    } else {
        request.method() == Method::Get
    };
    if !allowed {
        let allow = if record_route {
            ALLOW_CURSORLESS_RECORDS
        } else {
            ALLOW_RECORD_INDEX
        };
        return method_not_allowed_response(allow);
    }

    let Some(account_id) = account_id_param(&context) else {
        return error_response(STATUS_BAD_REQUEST, ErrorCode::InvalidRequest);
    };
    if record_route && record_id_param(&context).is_none() {
        return error_response(STATUS_BAD_REQUEST, ErrorCode::InvalidRequest);
    }
    forward_account_request(request, &context.env, account_id).await
}

async fn forward_account_request(
    request: Request,
    env: &Env,
    account_id: AccountId,
) -> worker::Result<Response> {
    let request = match request.method() {
        Method::Get => match forwarded_get_request(&request) {
            Ok(request) => request,
            Err(_) => return unavailable_response(),
        },
        Method::Put => match buffered_put_request(request).await {
            Ok(request) => request,
            Err(_) => return unavailable_response(),
        },
        _ => unreachable!("guarded account route method"),
    };
    let namespace = env.durable_object(ACCOUNT_OBJECT_BINDING)?;
    let stub = namespace.get_by_name(&account_id.to_string())?;
    match stub.fetch_with_request(request).await {
        Ok(response) => Ok(response),
        Err(_) => unavailable_response(),
    }
}

pub(crate) async fn handle_account_request(
    request: Request,
    state: &State,
    env: &Env,
) -> worker::Result<Response> {
    account_router(state).run(request, env.clone()).await
}

fn account_router<'a>(state: &'a State) -> Router<'a, &'a State> {
    Router::with_data(state)
        .post_async(INTERNAL_INITIALIZE_PATH, initialize_account)
        .get_async(ACCOUNT_RECORD_INDEX_ROUTE, route_account_request)
        .get_async(ACCOUNT_RECORD_ROUTE, route_account_request)
        .put_async(ACCOUNT_RECORD_ROUTE, route_account_request)
        .or_else_any_method("/", route_not_found)
        .or_else_any_method(ROUTER_FALLBACK_ROUTE, route_not_found)
}

#[derive(Clone, Copy)]
enum AccountOperation {
    ListRecords,
    GetRecord(RecordId),
    PutRecord(RecordId),
}

async fn route_account_request(
    request: Request,
    context: RouteContext<&State>,
) -> worker::Result<Response> {
    if context
        .param("account_id")
        .is_none_or(|value| value.is_empty())
    {
        return error_response(STATUS_NOT_FOUND, ErrorCode::InvalidRequest);
    }
    let Some(account_id) = account_id_param(&context) else {
        return error_response(STATUS_BAD_REQUEST, ErrorCode::InvalidRequest);
    };
    let operation = match (request.method(), context.param("record_id")) {
        (Method::Get, None) => AccountOperation::ListRecords,
        (method @ (Method::Get | Method::Put), Some(_)) => {
            let Some(record_id) = record_id_param(&context) else {
                return error_response(STATUS_BAD_REQUEST, ErrorCode::InvalidRequest);
            };
            if method == Method::Get {
                AccountOperation::GetRecord(record_id)
            } else {
                AccountOperation::PutRecord(record_id)
            }
        }
        _ => return error_response(STATUS_NOT_FOUND, ErrorCode::InvalidRequest),
    };
    let scope = match operation {
        AccountOperation::ListRecords | AccountOperation::GetRecord(_) => ApiKeyScope::Download,
        AccountOperation::PutRecord(_) => ApiKeyScope::Publish,
    };
    let authentication = authenticate_request(context.data, request.headers(), account_id, scope);
    // GET bodies are unused. Rejected PUTs must also release their stream before
    // returning, while authenticated PUTs retain it for bounded envelope parsing.
    if !matches!(operation, AccountOperation::PutRecord(_)) || authentication.is_err() {
        cancel_request_body(&request).await?;
    }
    match authentication {
        Ok(()) => {}
        Err(AuthenticationError::Unauthorized) => return unauthorized_response(),
        Err(AuthenticationError::Unavailable) => return unavailable_response(),
    }
    match operation {
        AccountOperation::ListRecords => list_records(context.data),
        AccountOperation::GetRecord(record_id) => get_record(context.data, record_id),
        AccountOperation::PutRecord(record_id) => {
            put_record(request, context.data, record_id).await
        }
    }
}

fn account_id_param<D>(context: &RouteContext<D>) -> Option<AccountId> {
    context
        .param("account_id")
        .and_then(|value| AccountId::parse(value).ok())
}

fn record_id_param<D>(context: &RouteContext<D>) -> Option<RecordId> {
    context
        .param("record_id")
        .and_then(|value| RecordId::parse(value).ok())
}

fn route_not_found<D>(_request: Request, _context: RouteContext<D>) -> worker::Result<Response> {
    error_response(STATUS_NOT_FOUND, ErrorCode::InvalidRequest)
}

fn handle_health(request: Request, _context: RouteContext<()>) -> worker::Result<Response> {
    if request.method() != Method::Get {
        return method_not_allowed_response(ALLOW_HEALTH);
    }
    empty_response(STATUS_NO_CONTENT)
}

async fn handle_accounts(
    mut request: Request,
    context: RouteContext<()>,
) -> worker::Result<Response> {
    if request.method() != Method::Post {
        return method_not_allowed_response(ALLOW_ACCOUNTS);
    }
    let body = match read_bounded_body(&mut request, MAX_API_BODY_BYTES).await {
        Ok(body) => body,
        Err(BodyReadError::TooLarge) => {
            return error_response(STATUS_PAYLOAD_TOO_LARGE, ErrorCode::TooLarge);
        }
        Err(BodyReadError::Unavailable) => return unavailable_response(),
    };
    if !body.is_empty() {
        return error_response(STATUS_BAD_REQUEST, ErrorCode::InvalidRequest);
    }

    create_account(&context.env).await
}

fn forwarded_get_request(request: &Request) -> worker::Result<Request> {
    let url = request.url()?;
    let headers = selected_headers(request, &["authorization"])?;
    let mut init = RequestInit::new();
    init.with_method(Method::Get).with_headers(headers);
    Request::new_with_init(url.as_str(), &init)
}

async fn buffered_put_request(mut request: Request) -> worker::Result<Request> {
    // Decouple the inbound stream before the Durable Object can reject a request
    // without reading its body. Otherwise workerd may keep reading after the
    // outer response has already been sent.
    let (body, too_large) = match read_bounded_body(&mut request, MAX_API_BODY_BYTES).await {
        Ok(body) => (body, false),
        Err(BodyReadError::TooLarge) => (Vec::new(), true),
        Err(BodyReadError::Unavailable) => {
            return Err(worker::Error::RustError(
                "request body forwarding failed".to_owned(),
            ));
        }
    };
    let url = request.url()?;
    let headers = selected_headers(&request, &["authorization"])?;
    if too_large {
        headers.set(INTERNAL_OVERSIZED_BODY_HEADER, "1")?;
    }
    let body = worker::js_sys::Uint8Array::from(body.as_slice());
    let mut init = RequestInit::new();
    init.with_method(Method::Put)
        .with_headers(headers)
        .with_body(Some(body.into()));
    Request::new_with_init(url.as_str(), &init)
}

fn selected_headers(request: &Request, names: &[&str]) -> worker::Result<Headers> {
    let selected = Headers::new();
    for name in names {
        if let Some(value) = header_value(request.headers(), name)? {
            selected.set(name, &value)?;
        }
    }
    Ok(selected)
}

async fn create_account(env: &Env) -> worker::Result<Response> {
    for _ in 0..MAX_ACCOUNT_ISSUANCE_ATTEMPTS {
        let issued = match issuance::issue() {
            Ok(issued) => issued,
            Err(_) => return unavailable_response(),
        };
        let publish_hash = issued.publish_token.service_hash();
        let download_hash = issued.download_token.service_hash();
        let stored = match StoredAccount::new(issued.account_id, publish_hash, download_hash) {
            Ok(stored) => stored,
            Err(_) => return unavailable_response(),
        };
        match initialize_remote_account(env, issued.account_id, stored).await? {
            InitializeOutcome::Created => {
                let response = CreateAccountResponse::new(
                    issued.account_id,
                    issued.publish_token,
                    issued.download_token,
                )
                .expect("issued Worker account satisfies the protocol invariants");
                return json_response(STATUS_CREATED, &response);
            }
            InitializeOutcome::AlreadyExists => continue,
        }
    }
    unavailable_response()
}

async fn initialize_remote_account(
    env: &Env,
    account_id: AccountId,
    account: StoredAccount,
) -> worker::Result<InitializeOutcome> {
    let encoded = account.encode();
    let body = worker::js_sys::Uint8Array::from(encoded.as_slice());
    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_body(Some(body.into()));
    // Durable Object calls use an internal HTTP-shaped request. The stub
    // selects the object; this synthetic URL supplies the private route.
    let request = Request::new_with_init(
        &format!("{INTERNAL_ORIGIN}{INTERNAL_INITIALIZE_PATH}"),
        &init,
    )?;
    let namespace = env.durable_object(ACCOUNT_OBJECT_BINDING)?;
    let stub = namespace.get_by_name(&account_id.to_string())?;
    let response = match stub.fetch_with_request(request).await {
        Ok(response) => response,
        Err(_) => {
            return Err(worker::Error::RustError(
                "account object unavailable".to_owned(),
            ));
        }
    };
    match response.status_code() {
        STATUS_NO_CONTENT => Ok(InitializeOutcome::Created),
        STATUS_CONFLICT => Ok(InitializeOutcome::AlreadyExists),
        _ => Err(worker::Error::RustError(
            "account object initialization failed".to_owned(),
        )),
    }
}

async fn initialize_account(
    mut request: Request,
    context: RouteContext<&State>,
) -> worker::Result<Response> {
    let encoded = match read_bounded_body(&mut request, ENCODED_ACCOUNT_BYTES).await {
        Ok(encoded) => encoded,
        Err(_) => return unavailable_response(),
    };
    let account = match StoredAccount::decode(&encoded) {
        Ok(account) => account,
        Err(_) => return unavailable_response(),
    };
    match storage::initialize(&context.data.storage(), &account) {
        Ok(InitializeOutcome::Created) => empty_response(STATUS_NO_CONTENT),
        Ok(InitializeOutcome::AlreadyExists) => empty_response(STATUS_CONFLICT),
        Err(_) => unavailable_response(),
    }
}

fn list_records(state: &State) -> worker::Result<Response> {
    let index = match storage::load_index(&state.storage()) {
        Ok(index) => index,
        Err(_) => return unavailable_response(),
    };
    json_response(STATUS_OK, &index)
}

fn get_record(state: &State, record_id: RecordId) -> worker::Result<Response> {
    let record = match storage::load_record(&state.storage(), record_id) {
        Ok(record) => record,
        Err(_) => return unavailable_response(),
    };
    match record {
        Some(record) => {
            let (envelope, revision) = record.into_envelope();
            let response = json_response(STATUS_OK, &envelope)?;
            etag_response(response, revision)
        }
        None => error_response(STATUS_NOT_FOUND, ErrorCode::InvalidRequest),
    }
}

async fn put_record(
    mut request: Request,
    state: &State,
    record_id: RecordId,
) -> worker::Result<Response> {
    // The public Worker drains oversized bodies and sets this private marker
    // because the sanitized request forwarded to the object has an empty body.
    if request.headers().has(INTERNAL_OVERSIZED_BODY_HEADER)? {
        cancel_request_body(&request).await?;
        return error_response(STATUS_PAYLOAD_TOO_LARGE, ErrorCode::TooLarge);
    }
    let body = match read_bounded_body(&mut request, MAX_API_BODY_BYTES).await {
        Ok(body) => body,
        Err(BodyReadError::TooLarge) => {
            return error_response(STATUS_PAYLOAD_TOO_LARGE, ErrorCode::TooLarge);
        }
        Err(BodyReadError::Unavailable) => return unavailable_response(),
    };
    let envelope = match Envelope::parse_json(&body) {
        Ok(envelope) => envelope,
        Err(attached_session_sync_protocol::api::ApiError::TooLarge) => {
            return error_response(STATUS_PAYLOAD_TOO_LARGE, ErrorCode::TooLarge);
        }
        Err(attached_session_sync_protocol::api::ApiError::InvalidRequest) => {
            return error_response(STATUS_BAD_REQUEST, ErrorCode::InvalidRequest);
        }
    };

    match storage::put_record(&state.storage(), record_id, envelope) {
        Ok(outcome) => mutation_success_response(outcome),
        Err(StoreError::Mutation(error)) => mutation_error_response(error),
        Err(StoreError::Unavailable) => unavailable_response(),
    }
}

enum AuthenticationError {
    Unauthorized,
    Unavailable,
}

fn authenticate_request(
    state: &State,
    headers: &Headers,
    account_id: AccountId,
    required_scope: ApiKeyScope,
) -> Result<(), AuthenticationError> {
    let value = header_value(headers, "authorization")
        .map_err(|_| AuthenticationError::Unauthorized)?
        .ok_or(AuthenticationError::Unauthorized)?;
    let token = ApiToken::parse_authorization(&[value.as_bytes()])
        .map_err(|_| AuthenticationError::Unauthorized)?;
    let account = storage::load_account(&state.storage())
        .map_err(|_| AuthenticationError::Unavailable)?
        .ok_or(AuthenticationError::Unauthorized)?;
    if account.account_id() != account_id {
        return Err(AuthenticationError::Unavailable);
    }
    if account.authenticate(&token.service_hash(), required_scope) {
        Ok(())
    } else {
        Err(AuthenticationError::Unauthorized)
    }
}

fn header_value(headers: &Headers, name: &str) -> worker::Result<Option<String>> {
    // The standard Headers.get API combines duplicates. Every caller either
    // parses strict grammar or compares the complete value, so combined values
    // are rejected without relying on the nonstandard Headers.getAll API.
    headers.get(name)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BodyReadError {
    TooLarge,
    Unavailable,
}

async fn cancel_request_body(request: &Request) -> worker::Result<()> {
    let Some(body) = request.inner().body() else {
        return Ok(());
    };
    worker::wasm_bindgen_futures::JsFuture::from(body.cancel())
        .await
        .map(|_| ())
        .map_err(worker::Error::from)
}

async fn read_bounded_body(request: &mut Request, limit: usize) -> Result<Vec<u8>, BodyReadError> {
    let mut too_large = request
        .headers()
        .get("content-length")
        .map_err(|_| BodyReadError::Unavailable)?
        .is_some_and(|length| {
            length
                .parse::<u64>()
                .is_ok_and(|length| length > limit as u64)
        });
    if request.inner().body().is_none() {
        return if too_large {
            Err(BodyReadError::TooLarge)
        } else {
            Ok(Vec::new())
        };
    }
    let mut stream = request.stream().map_err(|_| BodyReadError::Unavailable)?;
    let mut output = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| BodyReadError::Unavailable)?;
        if too_large {
            continue;
        }
        let Some(next) = output.len().checked_add(chunk.len()) else {
            output.clear();
            too_large = true;
            continue;
        };
        if next > limit {
            output.clear();
            too_large = true;
        } else {
            output.extend_from_slice(&chunk);
        }
    }
    if too_large {
        Err(BodyReadError::TooLarge)
    } else {
        Ok(output)
    }
}

fn mutation_success_response(outcome: MutationOutcome) -> worker::Result<Response> {
    let (status, revision) = match outcome {
        MutationOutcome::Created { revision } => (STATUS_CREATED, revision),
        MutationOutcome::Updated { revision } => (STATUS_NO_CONTENT, revision),
    };
    let response = empty_response(status)?;
    etag_response(response, revision)
}

fn mutation_error_response(error: MutationError) -> worker::Result<Response> {
    match error {
        MutationError::InvalidRequest => {
            error_response(STATUS_BAD_REQUEST, ErrorCode::InvalidRequest)
        }
        MutationError::LiveQuotaExceeded => {
            let response = error_response(STATUS_TOO_MANY_REQUESTS, ErrorCode::QuotaExceeded)?;
            set_header(response, "retry-after", "60")
        }
        MutationError::RevisionOverflow | MutationError::InvalidStorage => unavailable_response(),
    }
}

fn method_not_allowed_response(allow: &str) -> worker::Result<Response> {
    let response = error_response(STATUS_METHOD_NOT_ALLOWED, ErrorCode::InvalidRequest)?;
    set_header(response, "allow", allow)
}

fn unauthorized_response() -> worker::Result<Response> {
    let response = empty_response(STATUS_UNAUTHORIZED)?;
    set_header(response, "www-authenticate", AUTHENTICATE_VALUE)
}

pub(crate) fn unavailable_response() -> worker::Result<Response> {
    let response = error_response(STATUS_UNAVAILABLE, ErrorCode::Unavailable)?;
    set_header(response, "retry-after", "1")
}

fn json_response<T: serde::Serialize>(status: u16, value: &T) -> worker::Result<Response> {
    let response = Response::from_json(value)?.with_status(status);
    no_store(response)
}

fn error_response(status: u16, code: ErrorCode) -> worker::Result<Response> {
    json_response(status, &ErrorDto::new(code))
}

fn empty_response(status: u16) -> worker::Result<Response> {
    no_store(Response::empty()?.with_status(status))
}

fn no_store(response: Response) -> worker::Result<Response> {
    set_header(response, "cache-control", CACHE_CONTROL_VALUE)
}

fn etag_response(response: Response, revision: u64) -> worker::Result<Response> {
    set_header(response, "etag", &format!("\"{revision}\""))
}

fn set_header(response: Response, name: &str, value: &str) -> worker::Result<Response> {
    let headers = response.headers().clone();
    headers.set(name, value)?;
    Ok(response.with_headers(headers))
}
