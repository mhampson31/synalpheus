use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        println!("Create table Group");
        manager
            .create_table(
                Table::create()
                    .table(Group::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Group::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Group::Pk).string().unique_key().not_null())
                    .col(ColumnDef::new(Group::Name).string().not_null())
                    .col(
                        ColumnDef::new(Group::IsSuperuser)
                            .boolean()
                            .default(Value::Bool(Some(false))),
                    )
                    .col(
                        ColumnDef::new(Group::Parent)
                            .string()
                            .default(Value::String(None)),
                    )
                    .to_owned(),
            )
            .await?;

        println!("Create table Application");
        manager
            .create_table(
                Table::create()
                    .table(Application::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Application::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Application::Name).string().not_null())
                    .col(ColumnDef::new(Application::Slug).string().not_null())
                    .col(ColumnDef::new(Application::LaunchUrl).string().not_null())
                    .col(
                        ColumnDef::new(Application::Icon)
                            .string()
                            .default(Some("".to_string())),
                    )
                    .col(
                        ColumnDef::new(Application::Group)
                            .string()
                            .default(Some("".to_string())),
                    )
                    .to_owned()
                    .col(
                        ColumnDef::new(Application::Description)
                            .string()
                            .default(Some("".to_string())),
                    )
                    .to_owned(),
            )
            .await?;

        println!("Create table User");
        manager
            .create_table(
                Table::create()
                    .table(User::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(User::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(User::Pk).string().unique_key().not_null())
                    .col(ColumnDef::new(User::Username).string().not_null())
                    .col(
                        ColumnDef::new(User::IsSuperuser)
                            .boolean()
                            .default(Value::Bool(Some(false))),
                    )
                    .col(ColumnDef::new(User::Email).string().not_null())
                    .to_owned(),
            )
            .await?;

        println!("Create table UserGroup");
        manager
            .create_table(
                Table::create()
                    .table(UserGroup::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(UserGroup::UserPk).string())
                    .col(ColumnDef::new(UserGroup::GroupPk).string())
                    .primary_key(
                        Index::create()
                            .col(UserGroup::UserPk)
                            .col(UserGroup::GroupPk),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("FK_UserGroup_User")
                            .from(UserGroup::Table, UserGroup::UserPk)
                            .to(User::Table, User::Pk)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("FK_UserGroup_Group")
                            .from(UserGroup::Table, UserGroup::GroupPk)
                            .to(Group::Table, Group::Pk)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        println!("Drop table UserGroup");
        manager
            .drop_table(Table::drop().table(UserGroup::Table).to_owned())
            .await?;

        println!("Drop table Group");
        manager
            .drop_table(Table::drop().table(Group::Table).to_owned())
            .await?;

        println!("Drop table Application");
        manager
            .drop_table(Table::drop().table(Application::Table).to_owned())
            .await?;

        println!("Drop table User");
        manager
            .drop_table(Table::drop().table(User::Table).to_owned())
            .await?;

        Ok(())
    }
}

/// Learn more at https://docs.rs/sea-query#iden
#[derive(Iden)]
enum Group {
    Table,
    Id,
    Pk,
    Name,
    IsSuperuser,
    Parent,
}

#[derive(Iden)]
enum Application {
    Table,
    Id,
    Name,
    Slug,
    LaunchUrl,
    Icon,
    Group,
    Description,
}

#[derive(Iden)]
enum User {
    Table,
    Id,
    Pk,
    Username,
    IsSuperuser,
    Email,
}

#[derive(Iden)]
enum UserGroup {
    Table,
    UserPk,
    GroupPk,
}
