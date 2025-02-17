# Kypare
Kypare is a simple tool for serving static files over HTTPS. It generates its own CA certificate, and
on each start a new server certificate will be generated and signed by the CA.

The CA certificate is saved to a file when first generated, and will be loaded on subsequent starts of kypare.

It is mainly intended for testing purposes. For instance, browsers will not allow you to use certain DOM APIs from pages served over plain HTTP.

Kypare should absolutely not be used in any type of production context.

## Installation
`cargo install --git https://github.com/davids-work/kypare.git`

## Usage
By default `kypare` will serve files from the current working directory on https://localhost:8443. This behavior can be configured on the command line. Run `kypare --help` to see available options.