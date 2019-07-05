package messages

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func setupKG(t *testing.T) (*KeyGenerator, []byte) {
	secret := make([]byte, 64)
	_, err := rand.Read(secret)
	assert.Nil(t, err)

	generator := NewKeyGenerator(secret)
	generator.iterations = 2

	return generator, secret
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/key_generator_test.rb#L21
// we don't have implicit key length, so this isn't relevant

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/key_generator_test.rb#L27
func TestGeneratingKeyOfCustomLength(t *testing.T) {
	generator, _ := setupKG(t)

	derivedKey := generator.GenerateKey([]byte("some_salt"), 32)
	assert.Equal(t, 32, len(derivedKey), "Should have generated a key of the right size")
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/key_generator_test.rb#L33
func TestExpectedResults(t *testing.T) {
	// from https://github.com/rails/rails/blob/v5.2.3/activesupport/test/key_generator_test.rb#L34
	// > For any given set of inputs, this method must continue to return
	// > the same output: if it changes, any existing values relying on a
	// > key would break.

	secret := bytes.Repeat([]byte("0"), 64)

	keyGen := NewKeyGenerator(secret)

	expected, _ := hex.DecodeString("b129376f68f1ecae788d7433310249d65ceec090ecacd4c872a3a9e9ec78e055739be5cc6956345d5ae38e7e1daa66f1de587dc8da2bf9e8b965af4b3918a122")
	assert.Equal(t, expected, keyGen.GenerateKey([]byte("some_salt"), 64))

	expected, _ = hex.DecodeString("b129376f68f1ecae788d7433310249d65ceec090ecacd4c872a3a9e9ec78e055")
	assert.Equal(t, expected, keyGen.GenerateKey([]byte("some_salt"), 32))

	expected, _ = hex.DecodeString("cbea7f7f47df705967dc508f4e446fd99e7797b1d70011c6899cd39bbe62907b8508337d678505a7dc8184e037f1003ba3d19fc5d829454668e91d2518692eae")
	keyGen.iterations = 2
	assert.Equal(t, expected, keyGen.GenerateKey([]byte("some_salt"), 64))
}
