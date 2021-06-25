# poto

A small self-hosted URL redirector that integrates with a SAML2 IdP to authorize users who can add links.

Quick start:
1. Put your IdP metadata file in `app/metadata-idp.xml`
2. `docker-compose up`

Otherwise, customize environment variables in `docker-compose.yml` or use your favorite other orchestration.

Right now, this runs with the Flask debug server, so it isn't great security-wise. I'll fix this in the next few days.