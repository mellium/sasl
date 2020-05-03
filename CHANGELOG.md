# Changelog

All notable changes to this project will be documented in this file.


## Unreleased

### Fixed

- Return an error if no tls-unique channel binding (CB) data is present in the
  TLS connection state (or no connection state exists) and we use SCRAM with CB.
