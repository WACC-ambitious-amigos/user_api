use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct User {
    pub username: String,
    pub first_name: String,
    pub last_name: String,
    pub password: String,
    pub email: String,
}
