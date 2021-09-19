extern crate serde;
extern crate mongodb;

use mongodb::bson::{Document};
use mongodb::{error::Error, results::InsertOneResult, Collection};

pub mod models;
pub mod auth;

#[derive(Clone)]
pub struct UserService {
    collection: Collection,
}

impl UserService {
    pub fn new(collection: Collection) -> UserService {
        UserService { collection }
    }

    pub async fn create(&self, insert_doc: Document) -> Result<InsertOneResult, Error> {
        self.collection.insert_one(insert_doc, None).await
    }

    pub async fn get(&self, query_doc: Document) -> Result<Option<Document>, Error> {
        self.collection.find_one(query_doc, None).await
    }
}

#[cfg(test)]
mod tests {
    // TODO: Create tests
    #[test]
    fn creating_user() {
        assert!(true);
    }
}
