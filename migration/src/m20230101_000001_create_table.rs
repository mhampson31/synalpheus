use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Group::Table)
                    .if_not_exists()
                    .col(pk_auto(Group::Id))
                    .col(string(Group::Pk).unique_key())
                    .col(string(Group::Name))
                    .col(boolean(Group::IsSuperuser).default(Value::Bool(Some(false))))
                    .col(string(Group::Parent).default(Value::String(None)))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Application::Table)
                    .if_not_exists()
                    .col(pk_auto(Application::Id))
                    .col(string(Application::Name))
                    .col(string(Application::Slug))
                    .col(string(Application::LaunchUrl))
                    .col(string(Application::Icon).default(Some("".to_string())))
                    .col(string(Application::Group).default(Some("".to_string())))
                    .col(string(Application::Description).default(Some("".to_string())))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(User::Table)
                    .if_not_exists()
                    .col(pk_auto(User::Id))
                    .col(string(User::Pk).unique_key())
                    .col(string(User::Username))
                    .col(boolean(User::IsSuperuser).default(Value::Bool(Some(false))))
                    .col(string(User::Email))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(UserGroup::Table)
                    .if_not_exists()
                    .col(string(UserGroup::UserPk))
                    .col(string(UserGroup::GroupPk))
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
        manager
            .drop_table(Table::drop().table(Application::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(UserGroup::Table).if_exists().to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(Group::Table).if_exists().to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(User::Table).if_exists().to_owned())
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
