# entra id cert sync script

This program can fetch the XML metadata file from microsoft ENTRA ID and select the correct cert to then patch eLabFTW IDP with that new cert.

Run it every hour or so in a cronjob.

## Configuration

Configuration through ENV variables:

`METADATA_URL`: https://login.microsoftonline.com/UUU-VVV-ZZZ-YYY-XXXX/federationmetadata/2007-06/federationmetadata.xml
`ELABFTW_HOST`: https://elabftw.example.org
`ELABFTW_API_KEY`: 12-abcde123...
`ELABFTW_IDP_ID`: 2

Optional configuration parameters:

`VERBOSE`: 1
`FORCE_PATCH`: 1
`REQUIRED_SUBJECT_CN`: "login.microsoftonline.us"

## Usage

You can have a .env file with KEY=value (no quotes) and use --env-file .env in the run command.

`docker run --env-file .env --rm deltablot/entra-cert-watch`

## Dev

Format: uvx ruff format
