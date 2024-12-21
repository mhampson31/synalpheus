# synalpheus
Synalpheus is a dashboard that uses Authentik's APIs to automatically displaying the logged-in user's list of applications. As of 0.4.3, Synalpheus is mostly feature-complete.

![A screenshot of Synalpheus](/screenshot.png?raw=true "Synalpheus")

Authentik does have a perfectly good dashboard built in. So why Synalpheus? Two reasons: First, in practical terms, I wanted a dashboard I could run on a different subdomain than Authentik. And second, this project is a personal learning exercise, to develop my understanding of the Rust ecosystem. Other features are planned.

Synalpheus is not likely to work out of the box with other auth providers -- it expects to be able to make requests against an Authentik API, and deserialize the response according to its schema.

What works as of v0.4.5?
* Login/logout via Authentik
* Retrieving user data, including applications the user can access, from Authentik
* Storing info about applications you're not managing via Authentik in your Postgres database
* Storing and serving icon images for your non-Authentik apps
* Displaying the applications to the user
* Redis sessions
* Docker integration

Still todo:
* Better handling and logging of errors
* Cleanup and refactoring of the code

Setup:
1. Ensure you have a working Authentik setup (version 2024.6 or later is required)
2. Add a new OAuth2 app in your Authentik environment for Synalpheus with the following scopes:
  * openid
  * profile
  * email
  * offline_access
  * goauthentik.io/api
3. Configure the .env file for Synalpheus with the appropriate fields
4. Create a new user in Postgres -- Synalpheus doesn't share a DB user or access with Authentik
5. Add a service for Synalpheus to your docker-compose.yml:

```yaml
  synalpheus:
    image: toxotes/synalpheus:latest
    container_name: synalpheus
    restart: unless-stopped
    depends_on:
      - authentik-server
    ports:
      - 8080:80
    volumes:
      # Synalpheus will use this to store images files for any non-Authentik applications
      - /opt/appdata/synalpheus:/synalpheus/media
    environment:
      PUID: ${PUID}
      PGUID: ${PGID}
      SYN_AUTHENTIK_URL: [your Authentik URL]
      SYN_URL: [your Synalpheus URL]
      SYN_CLIENT_ID: ${SYN_CLIENT_ID} # Synalpheus's client ID in Authentik
      SYN_CLIENT_SECRET: ${SYN_CLIENT_SECRET} # Synalpheus's client secret in Authentik
      SYN_REDIRECT_PATH: "/auth/authentik"
      SYN_PROVIDER: "Synalpheus"
      SYN_POSTGRES_URL: "postgres://[db user]:[db password]@postgres/synalpheus"
```
