package messages

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func setupMV(t *testing.T) (MessageVerifier, []byte, []byte) {
	verifier := NewMessageVerifierSHA1([]byte("Hey, I'm a secret!"))
	assert.NotNil(t, verifier)

	data := map[string]interface{}{
		"some": "data",
		"now":  time.Date(2010, time.November, 10, 23, 0, 0, 0, time.UTC),
	}
	dataBytes, err := json.Marshal(data)
	assert.Nil(t, err)

	secret := make([]byte, 32)
	_, err = rand.Read(secret)
	assert.Nil(t, err)

	return verifier, dataBytes, secret
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_verifier_test.rb#L26
func TestValidMessage(t *testing.T) {
	verifier, exampleData, _ := setupMV(t)

	allBytes, err := verifier.Generate(exampleData)
	assert.Nil(t, err)

	parts := bytes.Split(allBytes, []byte("--"))
	data := parts[0]
	hash := parts[1]

	// assert !@verifier.valid_message?(nil)
	assert.False(t, verifier.IsValidMessage(nil))
	// assert !@verifier.valid_message?("")
	assert.False(t, verifier.IsValidMessage([]byte("")))
	// assert !@verifier.valid_message?("\xff") # invalid encoding
	assert.False(t, verifier.IsValidMessage([]byte("\xff")))
	// assert !@verifier.valid_message?("#{data.reverse}--#{hash}")
	assert.False(t, verifier.IsValidMessage(bytes.Join([][]byte{reverse(data), hash}, []byte("--"))))
	// assert !@verifier.valid_message?("#{data}--#{hash.reverse}")
	assert.False(t, verifier.IsValidMessage(bytes.Join([][]byte{data, reverse(hash)}, []byte("--"))))
	// assert !@verifier.valid_message?("purejunk")
	assert.False(t, verifier.IsValidMessage([]byte("purejunk")))

	// not in rails, but validates the positive case too
	t.Logf("Message is %s", allBytes)
	assert.True(t, verifier.IsValidMessage(allBytes))
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_verifier_test.rb#L36
func TestSimpleRoundTripping(t *testing.T) {
	verifier, exampleData, _ := setupMV(t)

	allBytes, err := verifier.Generate(exampleData)
	assert.Nil(t, err)

	// assert_equal @data, @verifier.verified(message)
	// assert_equal @data, @verifier.verify(message)
	out, err := verifier.Verify(allBytes, nil)
	assert.Nil(t, err)
	assert.Equal(t, exampleData, out)
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_verifier_test.rb#L42
// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_verifier_test.rb#L46 (no exceptions in go, we return err)
func TestVerifiedReturnsFalseOnInvalidMessage(t *testing.T) {
	verifier, _, _ := setupMV(t)

	// assert !@verifier.verified("purejunk")
	out, err := verifier.Verify([]byte("purejunk"), nil)
	assert.NotNil(t, err)
	assert.Nil(t, out)
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_verifier_test.rb#L52
// we don't use automatic serialization in Go: we only take a []byte for simplicity

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_verifier_test.rb#L64
// because of the same as above, we don't magically deserialize complex Ruby objects

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_verifier_test.rb#L83
func TestRaiseErrorWhenSecretIsNil(t *testing.T) {
	// there are no exceptions in Go, so we ensure that we return nil rather than secrely allowing nil-secret signing
	verifier := NewMessageVerifierSHA1(nil)
	assert.Nil(t, verifier)
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_verifier_test.rb#L90
func TestBackwardCompatibilityMessagesSignedWithoutMetadata(t *testing.T) {
	verifier, _, _ := setupMV(t)

	signedMessage := "BAh7BzoJc29tZUkiCWRhdGEGOgZFVDoIbm93SXU6CVRpbWUNIIAbgAAAAAAHOgtvZmZzZXRpADoJem9uZUkiCFVUQwY7BkY=--d03c52c91dfe4ccc5159417c660461bcce005e96"

	// assert_equal @data, @verifier.verify(signed_message)
	data, err := verifier.Verify([]byte(signedMessage), nil)
	assert.Nil(t, err)
	assert.NotNil(t, data)
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_verifier_test.rb#L95
func TestRotatingSecret(t *testing.T) {
	_, _, secret := setupMV(t)

	// old_message = ActiveSupport::MessageVerifier.new("old", digest: "SHA1").generate("old")
	oldVerifier := NewMessageVerifierSHA1([]byte("old"))
	assert.NotNil(t, oldVerifier)

	oldMessage, err := oldVerifier.Generate([]byte("old"))
	assert.Nil(t, err)
	assert.NotNil(t, oldMessage)

	// verifier = ActiveSupport::MessageVerifier.new(@secret, digest: "SHA1")
	// verifier.rotate "old"
	verifier := NewRotatingMessageVerifier(
		NewMessageVerifierSHA1(secret),
		NewMessageVerifierSHA1([]byte("old")),
	)
	assert.NotNil(t, verifier)

	// assert_equal "old", verifier.verified(old_message)
	data, err := verifier.Verify([]byte(oldMessage), nil)
	assert.Nil(t, err)
	assert.Equal(t, []byte("old"), data)
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_verifier_test.rb#L104
func TestMultipleRotations(t *testing.T) {
	_, _, secret := setupMV(t)

	oldVerifier := NewMessageVerifierSHA256([]byte("old"))
	oldMessage, err := oldVerifier.Generate([]byte("old"))
	assert.Nil(t, err)

	olderVerifier := NewMessageVerifierSHA1([]byte("older"))
	olderMessage, err := olderVerifier.Generate([]byte("older"))
	assert.Nil(t, err)

	newVerifier := NewMessageVerifierSHA512(secret)

	verifier := NewRotatingMessageVerifier(
		newVerifier,
		oldVerifier,
		olderVerifier,
	)

	newMessage, err := verifier.Generate([]byte("new"))
	assert.Nil(t, err)

	v, err := verifier.Verify(newMessage, nil)
	assert.Nil(t, err)
	assert.Equal(t, []byte("new"), v)

	v, err = verifier.Verify(oldMessage, nil)
	assert.Nil(t, err)
	assert.Equal(t, []byte("old"), v)

	v, err = verifier.Verify(olderMessage, nil)
	assert.Nil(t, err)
	assert.Equal(t, []byte("older"), v)

	// not in rails, but this tests that the newest one is used for signing
	v, err = newVerifier.Verify(newMessage, nil)
	assert.Nil(t, err)
	assert.Equal(t, []byte("new"), v)

	// rails doesn't do this, but also test IsValidMessage for completeness
	assert.True(t, verifier.IsValidMessage(newMessage))
	assert.True(t, verifier.IsValidMessage(oldMessage))
	assert.True(t, verifier.IsValidMessage(olderMessage))
	assert.True(t, newVerifier.IsValidMessage(newMessage))
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_verifier_test.rb#L117
// we don't have an on_rotation

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_verifier_test.rb#L131
func TestRotationWithMetadata(t *testing.T) {
	_, _, secret := setupMV(t)

	// oldMessage = ActiveSupport::MessageVerifier.new("old").generate("old", purpose: :rotation)
	oldVerifier := NewMessageVerifierSHA1([]byte("old"))
	purpose := "rotation"
	oldMessage, err := oldVerifier.GenerateWithMetadata([]byte("old"), &purpose, nil)
	assert.Nil(t, err)

	verifier := NewRotatingMessageVerifier(
		NewMessageVerifierSHA1(secret),
		oldVerifier,
	)

	// assert_equal "old", verifier.verified(old_message, purpose: :rotation)
	purpose = "rotation"
	v, err := verifier.Verify(oldMessage, &purpose)
	assert.Nil(t, err)
	assert.Equal(t, []byte("old"), v)

	// not in rails, but also check metadata during rotation in the negative case
	purpose = "something else"
	v, err = verifier.Verify(oldMessage, &purpose)
	assert.NotNil(t, err)
	assert.Nil(t, v)

	// not in rails, but also check metadata during rotation with a nil purpose
	v, err = verifier.Verify(oldMessage, nil)
	assert.NotNil(t, err)
	assert.Nil(t, v)
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_verifier_test.rb#L148
func TestVerifyErrorsWhenPurposeDiffers(t *testing.T) {
	verifier, _, _ := setupMV(t)

	purpose := "payment"
	paymentMessage, err := verifier.GenerateWithMetadata([]byte("old"), &purpose, nil)
	assert.NotNil(t, paymentMessage)
	assert.Nil(t, err)

	otherPurpose := "shipping"
	v, err := verifier.Verify(paymentMessage, &otherPurpose)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "purpose did not match")
	assert.Nil(t, v)
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_verifier_test.rb#L154
func TestVerifyErrorsWhenExpired(t *testing.T) {
	verifier, _, _ := setupMV(t)

	pastTime := time.Now().Add(-time.Hour * 24)
	expiredMessage, err := verifier.GenerateWithMetadata([]byte("old"), nil, &pastTime)
	assert.NotNil(t, expiredMessage)
	assert.Nil(t, err)

	v, err := verifier.Verify(expiredMessage, nil)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "message has expired")
	assert.Nil(t, v)
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_verifier_test.rb#L177
// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_verifier_test.rb#L184
// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_verifier_test.rb#L191
// we don't use serializers, only allowing []byte as the data type, so these are not valid here.

func TestNilVerifiersOnRotation(t *testing.T) {
	rotating := NewRotatingMessageVerifier(nil)
	assert.Nil(t, rotating)
}

func reverse(s []byte) []byte {
	ns := make([]byte, len(s))
	copy(ns, s)
	for i := 0; i < len(s)/2; i++ {
		j := len(s) - i - 1
		ns[i], ns[j] = ns[j], ns[i]
	}
	return ns
}
