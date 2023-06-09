# Kypare
Kypare is a simple tool for serving static files over HTTPS. It has a built-in self-signed certificate to save the user the trouble of generating one.

It is mainly intended for testing purposes. For instance, browsers will not allow you to use certain DOM APIs from pages served over plain HTTP.

Kypare should absolutely not be used in any type of production context.

## Installation
`cargo install --git https://github.com/davids-work/kypare.git`

## Usage
By default `kypare` will serve files from the current working directory on https://localhost:8080. This behavior can be configured on the command line. Run `kypare --help` to see available options.