package messages

import (
	"crypto/sha1"

	"golang.org/x/crypto/pbkdf2"
)

// KeyGenerator is a Go version of ActiveSupport::KeyGenerator, designed to mimick that API as closely as possible
type KeyGenerator struct {
	secret     []byte
	iterations int
}

func NewKeyGenerator(secret []byte) *KeyGenerator {
	// matches https://github.com/rails/rails/blob/v5.2.3/activesupport/lib/active_support/key_generator.rb#L16
	return NewKeyGeneratorWithIterations(secret, 65536)
}

func NewKeyGeneratorWithIterations(secret []byte, iterations int) *KeyGenerator {
	return &KeyGenerator{
		secret:     secret,
		iterations: iterations,
	}
}

func (kg *KeyGenerator) GenerateKey(salt []byte, keySize int) []byte {
	// matches https://github.com/rails/rails/blob/v5.2.3/activesupport/lib/active_support/key_generator.rb#L23
	return pbkdf2.Key(kg.secret, salt, kg.iterations, keySize, sha1.New)
}
