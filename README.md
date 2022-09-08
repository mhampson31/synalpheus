# gonkboard
A dashboard for Authentik-supported apps

Gonkboard is a dashboard that integrates with Authentik, automatically displaying the logged-in user's list of applications.

Authentik does have a perfectly good dashboard built in. So why Gonkboard? Two reasons: First, in practical terms, I wanted a dashboard I could run on a different subdomain than Authentik. And second, this project is a personal learning exercise, to develop my understanding of the Rust ecosystem.

This is all still very incomplete. 

Setup:
1. Add a new OAuth2 app in your Authentik environment for Gonkboard
2. Configure the .env file for Gonkboard with the appropriate fields
