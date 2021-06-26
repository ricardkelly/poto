# poto

A small self-hosted URL redirector that integrates with a SAML2 IdP to authorize users who can add links.

Quick start to try it out:
1. Put your IdP metadata file in `app/metadata-idp.xml`
2. `docker-compose up`

Otherwise, customize environment variables in `docker-compose.yml` or use your favorite other orchestration for development.

`docker-compose -f docker-compose-prod.yml up` will bring up the application behind a proper WSGI web service.
