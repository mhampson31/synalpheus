# Changelog

What's new in Synalpheus?

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). (Or tries to anyway.)

## [0.10.0] - 2026-09-03
- New theming, including a theme selector
- Better responsive design

## [0.9.0] - 2026-09-01
- Changed CSS framework from Bulma to daisyUI/Tailwind

## [0.8.0] - 2026-08-30
- *Important!* Synalpheus now uses a _config.toml_ file instead of _.env_. Please see the new sample file.
- Authentik's "Hide from Application Dashboard" setting is now observed  
- Lots of refactoring and code cleanup

## [0.7.0] - 2026-08-23
- Removed Redis as the session storage, since Authentik no longer uses it
- Updated Tera and SeaORM to their v2 releases
- Other smaller version bumps

## [0.6.1] - 2026-04-23
- Version bumps

## [0.6.0] - 2026-01-21
- Version bumps
- Fixed an error with icons due to a change in the Authentik API
- Makes the page title configurable

## [v0.5.1] - 2025-12-21
- Version bumps, it's been a while
- Rust edition bump to 2024
- Improved logging
 
## [v0.5.0] - 2025-03-15
- Updated SeaORM version in migrations and entities
- Refactored migration for SeaORM's new format
- Removed some tables from the initial migration that we ended up not needing
- Run pending migrations on app boot

## [v0.4.5] - 2024-12-28
- Updated the app card layout so sizing should be more consistent.
- Fixed local icon issues caused by Docker configuration. NOTE: the persistant local volume should now map to /synalpheus/media
- Limit local app access by group: if the local app is in a group, the user must be as well in order to see it
- Version bumps for frontend libraryes: Bulma, HTMX, and Hyperscript

## [v0.4.4] - 2024-12-20
- Code refactoring and cleanup
- Version bump of Rust and several libraries

## [v0.4.3] - 2024-07-13
- Added the ability to upload icons for locally-managed applications

## [v0.4.2] - 2024-06-30
- Now uses Authentik's OIDC .well-known endpoint for OAuth2 configuration
- Brought the sample .env file up to date
- Added a favicon, finally

## [v0.4.1] - 2024-06-29
- Fixed an issue where the user's Authentik access was not being refreshed when it could be

## [v0.4.0] - 2024-05-14
- Moved to Bulma 1.0 and updated some of the styling. Now supports dark mode.
- Updated to HTMX 2.0

## [v0.3.4] - 2024-05-14
- Version bump of dependencies, most significantly Poem 3.0

## [v0.3.3] - 2023-12-26
- CSS tweaks to the homepage: Each app card is now a link to its launch_url, if it has one
- Dependency updates
- Added this changelog

## [v0.3.2 and below]
- Everything not mentioned above. Sorry!
