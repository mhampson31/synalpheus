use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "user")]
pub struct Model {
    #[sea_orm(primary_key)]
    #[serde(skip_deserializing)]
    pub id: i32,
    email: String,
    name: String,
    #[serde(rename(deserialize = "preferred_username"))]
    #[sea_orm(ignore)]
    preferred_username: String,
    #[sea_orm(ignore)]
    groups: Option<Vec<String>>,
    #[sea_orm(ignore)]
    sub: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
