#![forbid(unsafe_code)]

mod api;
mod issuance;
mod model;
mod storage;

use worker::{
    Context, DurableObject, Env, Request, Response, Result, State, durable_object, event,
};

#[event(fetch)]
pub async fn fetch(request: Request, env: Env, _context: Context) -> Result<Response> {
    match api::handle_public_request(request, &env).await {
        Ok(response) => Ok(response),
        Err(_) => {
            worker::console_error!("session synchronization Worker request failed");
            api::unavailable_response()
        }
    }
}

#[durable_object]
pub struct AccountObject {
    state: State,
    env: Env,
}

impl DurableObject for AccountObject {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, request: Request) -> Result<Response> {
        match api::handle_account_request(request, &self.state, &self.env).await {
            Ok(response) => Ok(response),
            Err(_) => {
                worker::console_error!("session synchronization account object request failed");
                api::unavailable_response()
            }
        }
    }
}
