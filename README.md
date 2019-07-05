# go-activecompat

This repository hosts a faithfully re-implemented version of the `Messsage*` classes from [Rails Active Support](https://github.com/rails/rails/tree/master/activesupport), along with all their tests. These classes are designed to behave as similarly as possible to the Rails equivilent to provide compatibility, while still respecting the expectations of Go libraries.

Logic in this package has extensive back-references to Rails code to where the similar logic is implemented there, to aid in validating that functionality is matched.

Installation:
```
go get github.com/theojulienne/go-activecompat
```

## `messages` package

[![GoDoc](https://godoc.org/github.com/theojulienne/go-activecompat/pkg/messages?status.svg)](https://godoc.org/github.com/theojulienne/go-activecompat/pkg/messages)

Classes provided:
 * `KeyGenerator` - [Go docs](https://godoc.org/github.com/theojulienne/go-activecompat/pkg/messages#KeyGenerator), [Ruby/Rails docs](https://edgeapi.rubyonrails.org/classes/ActiveSupport/KeyGenerator.html)
 * `MessageEncryptor` - [Go docs](https://godoc.org/github.com/theojulienne/go-activecompat/pkg/messages#MessageEncryptor), [Ruby/Rails docs](https://api.rubyonrails.org/v5.2.3/classes/ActiveSupport/MessageEncryptor.html)
 * `MessageVerifier` - [Go docs](https://godoc.org/github.com/theojulienne/go-activecompat/pkg/messages#MessageVerifier), [Ruby/Rails docs](https://api.rubyonrails.org/v5.2.3/classes/ActiveSupport/MessageVerifier.html)

The Rails documentation is more complete, and generally the Go version should be used in the same way. Additionally, metadata is fully supported and both string purposes and message expirations can be provided and validated.

Differences from Rails:
 * Serialization and deserialisation is not supported, all classes return messages as `[]byte`. Calling classes should handle marshaling, and generally should use JSON for improved compatibility.
 * Key and cipher rotation is provided by `RotatingMessageEncryptor` and `RotatingMessageVerifier` which compose and implement the same `MessageEncryptor` and `MessageVerifier` interfaces, rather than having a `rotate` method.

Example usage:
```go
package main

import (
	"fmt"

	"github.com/theojulienne/go-activecompat/pkg/messages"
)

const (
	// these are constant salts used by Rails and match those
	// in config.action_dispatch.encrypted_*
	signed_cookie_salt                  = "signed cookie"
	encrypted_cookie_salt               = "encrypted cookie"
	encrypted_signed_cookie_salt        = "signed encrypted cookie"
	authenticated_encrypted_cookie_salt = "authenticated encrypted cookie"

	SecretKeyBase = "thisisnotsecure"
)

// creates a new Rails-compatible session decryptor/verifier
func newRailsSessionEncryptor() messages.MessageEncryptor {
	keyLen := messages.GetMessageEncryptorKeyLength(messages.RailsDefaultAuthenticatedMessageEncryptionCipher)
	// 1k iterations used by rails default here: https://github.com/rails/rails/blob/v5.2.3/railties/lib/rails/application.rb#L173-L178
	keyGen := messages.NewKeyGeneratorWithIterations([]byte(SecretKeyBase), 1000)
	authenticatedEncryptedCookieKey := keyGen.GenerateKey([]byte(authenticated_encrypted_cookie_salt), keyLen)

	return messages.NewMessageEncryptor(authenticatedEncryptedCookieKey, authenticatedEncryptedCookieKey, messages.RailsDefaultAuthenticatedMessageEncryptionCipher)
}

func main() {
	crypt := newRailsSessionEncryptor()

	// generate a session, which Rails would understand
	json := "{\"testing\": \"foo\"}"

	cookie, err := crypt.EncryptAndSign([]byte(json), nil, nil)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Rails session cookie would contain: %v\n", string(cookie))

	// now round-trip back to the original
	cookieBytes, err := crypt.DecryptAndVerify(cookie, nil)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Round-tripped session contents: %v\n", string(cookieBytes))
}

```
