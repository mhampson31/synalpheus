# synalpheus
Synalpheus is a dashboard that uses Authentik's APIs to automatically displaying the logged-in user's list of applications. This is all still very incomplete, but it is fairly functional already.

Authentik does have a perfectly good dashboard built in. So why Synalpheus? Two reasons: First, in practical terms, I wanted a dashboard I could run on a different subdomain than Authentik. And second, this project is a personal learning exercise, to develop my understanding of the Rust ecosystem. Other features are planned.

Synalpheus is not likely to work out of the box with other auth providers -- it expects to be able to make requests against an Authentik API, and deserialize the response according to its schema.

What works as of v.03?
* Login/logout, although logout is probably naive
* Retrieving user data, including applications the user can access, from Authentik
* Displaying the applications to the user
* Redis sessions
* Docker integration
* Reading application info stored in your PostGres database (but not writing to it yet)

Future work:
* Finishing CRUD for local (non-Authentik) applications
* User-added bookmark links
* Substantial prettification

Setup:
1. Ensure you have a working Authentik setup (version 2022.7 or later)
2. Add a new OAuth2 app in your Authentik environment for Synalpheus
3. Configure the .env file for Synalpheus with the appropriate fields
