use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "user")]
pub struct Model {
    #[sea_orm(primary_key)]
    #[serde(skip_deserializing)]
    pub id: i32,
    pub email: String,
    pub name: String,
    #[serde(rename(deserialize = "preferred_username"))]
    #[sea_orm(ignore)]
    pub preferred_username: String,
    #[sea_orm(ignore)]
    pub groups: Option<Vec<String>>,
    #[sea_orm(ignore)]
    pub sub: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
