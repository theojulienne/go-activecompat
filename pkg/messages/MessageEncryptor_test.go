package messages

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func setupME(t *testing.T) (MessageVerifier, MessageEncryptor, []byte, []byte) {
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	assert.Nil(t, err)

	verifier := NewMessageVerifierSHA1(secret)
	assert.NotNil(t, verifier)

	data := map[string]interface{}{
		"some": "data",
		"now":  time.Date(2010, time.November, 10, 23, 0, 0, 0, time.UTC),
	}
	dataBytes, err := json.Marshal(data)
	assert.Nil(t, err)

	// class default is false (non-auth), so we use that here
	// see: https://github.com/rails/rails/blob/v5.2.3/activesupport/lib/active_support/message_encryptor.rb#L85
	// tests below expect this one to be using MessageVerifier under the hood.
	encryptor := NewMessageEncryptor(secret, secret, RailsDefaultNonAuthenticatedMessageEncryptionCipher)
	assert.NotNil(t, encryptor)

	return verifier, encryptor, dataBytes, secret
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_encryptor_test.rb#L27
func TestEncryptingTwiceYieldsDifferingCipherText(t *testing.T) {
	_, encryptor, exampleData, _ := setupME(t)

	firstMessage, err := encryptor.EncryptAndSign(exampleData, nil, nil)
	assert.Nil(t, err)
	secondMessage, err := encryptor.EncryptAndSign(exampleData, nil, nil)
	assert.Nil(t, err)

	assert.NotEqual(t, bytes.Split(firstMessage, []byte("--"))[0], bytes.Split(secondMessage, []byte("--"))[0])
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_encryptor_test.rb#L33
func TestMessingWithEitherEncryptedValuesCausesFailure(t *testing.T) {
	verifier, encryptor, exampleData, _ := setupME(t)

	message, err := encryptor.EncryptAndSign(exampleData, nil, nil)
	assert.Nil(t, err)

	verified, err := verifier.Verify(message, nil)
	assert.Nil(t, err)

	parts := bytes.Split(verified, []byte("--"))
	text := parts[0]
	iv := parts[1]

	assertDecryptionFails(t, verifier, encryptor, bytes.Join([][]byte{iv, text}, []byte("--")), "iv had incorrect length")
	// rails expects these to "fail", but because they are verified but decrypted wrong, the data will just be invalid
	assertDecryptsToInvalid(t, verifier, encryptor, bytes.Join([][]byte{text, munge(iv)}, []byte("--")), exampleData)
	assertDecryptionFails(t, verifier, encryptor, bytes.Join([][]byte{munge(text), iv}, []byte("--")), "bad padding bytes")
	assertDecryptionFails(t, verifier, encryptor, bytes.Join([][]byte{munge(text), munge(iv)}, []byte("--")), "bad padding bytes")
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_encryptor_test.rb#L41
func TestMessingWithVerifiedValuesCausesFailure(t *testing.T) {
	_, encryptor, exampleData, _ := setupME(t)

	message, err := encryptor.EncryptAndSign(exampleData, nil, nil)
	assert.Nil(t, err)

	parts := bytes.Split(message, []byte("--"))
	text := parts[0]
	iv := parts[1]

	assertNotVerified(t, encryptor, bytes.Join([][]byte{iv, text}, []byte("--")))
	assertNotVerified(t, encryptor, bytes.Join([][]byte{text, munge(iv)}, []byte("--")))
	assertNotVerified(t, encryptor, bytes.Join([][]byte{munge(text), iv}, []byte("--")))
	assertNotVerified(t, encryptor, bytes.Join([][]byte{munge(text), munge(iv)}, []byte("--")))
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_encryptor_test.rb#L49
func TestSignedRoundTripping(t *testing.T) {
	_, encryptor, exampleData, _ := setupME(t)

	message, err := encryptor.EncryptAndSign(exampleData, nil, nil)
	assert.Nil(t, err)

	original, err := encryptor.DecryptAndVerify(message, nil)
	assert.Nil(t, err)
	assert.Equal(t, exampleData, original)
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_encryptor_test.rb#L54
func TestBackwardsCompatFor64BytesKey(t *testing.T) {
	secret, err := hex.DecodeString("3942b1bf81e622559ed509e3ff274a780784fe9e75b065866bd270438c74da822219de3156473cc27df1fd590e4baf68c95eeb537b6e4d4c5a10f41635b5597e")
	assert.Nil(t, err)

	encryptor := NewMessageEncryptor(secret[0:32], secret, RailsDefaultNonAuthenticatedMessageEncryptionCipher)
	assert.NotNil(t, encryptor)

	message := []byte("eHdGeExnZEwvMSt3U3dKaFl1WFo0TjVvYzA0eGpjbm5WSkt5MXlsNzhpZ0ZnbWhBWFlQZTRwaXE1bVJCS2oxMDZhYVp2dVN3V0lNZUlWQ3c2eVhQbnhnVjFmeVVubmhRKzF3WnZyWHVNMDg9LS1HSisyakJVSFlPb05ISzRMaXRzcFdBPT0=--831a1d54a3cda8a0658dc668a03dedcbce13b5ca")
	decrypted, err := encryptor.DecryptAndVerify(message, nil)
	assert.Nil(t, err)

	// The below 'expected' string is the plaintext for the following.
	// Since we don't handle marshaling, just port the test by ensuring the exact plaintext matches.
	// => {:some=>"data", :now=>2010-01-01 00:00:00 -0800}
	expected, err := hex.DecodeString("04087b073a09736f6d6549220964617461063a0645543a086e6f7749753a0954696d650d28801b8000000000073a0b6f666673657469fe808f3a097a6f6e65492208505354063b0646")
	assert.Equal(t, expected, decrypted)
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_encryptor_test.rb#L64
// we don't support automatic serialization, so this test doesn't make sense

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_encryptor_test.rb#L75
// everything about the above function seems broken (it fails as expected because it generates
// invalid data, not because of base64 encoding), so writing based on what this _should_ be doing
func TestMessageObeysStrictEncoding(t *testing.T) {
	verifier, encryptor, _, _ := setupME(t)

	badEncodingCharacters := []byte("\n!@#")

	originalData := []byte("This is a very \n\nhumble string")
	encrypted, err := encryptor.EncryptAndSign(originalData, nil, nil)
	assert.Nil(t, err)

	// rails seems to take the above, which would be a verified message, and treat it as msg+iv
	// instead what they probably wanted was to verify the message (like we did in TestMessingWithEitherEncryptedValuesCausesFailure)
	// then pull out the underlying encrypted message+iv from that.
	verified, err := verifier.Verify(encrypted, nil)
	assert.Nil(t, err)

	// rails calls these:
	//   assert_not_decrypted("#{::Base64.encode64 message.to_s}--#{::Base64.encode64 iv.to_s}")
	//   assert_not_decrypted([iv,  message] * bad_encoding_characters)
	// since these are going to re-verify things, we need to use the unwrapped message+iv
	// oddly, neither of these are valid anyway. instead, let's add badEncodingCharacters to the
	// middle of the message, since this is what Strict actually changes
	for _, evilChar := range badEncodingCharacters {
		evilString := bytes.Join([][]byte{verified[:20], []byte{evilChar}, verified[21:]}, []byte{})
		assertDecryptionFails(t, verifier, encryptor, []byte(evilString), "illegal base64 data")
	}

	// rails calls these:
	//   assert_not_verified("#{::Base64.encode64 message.to_s}--#{::Base64.encode64 iv.to_s}")
	//   assert_not_verified([iv,  message] * bad_encoding_characters)
	// in which we want to test the the _verification_ breaks, so we want to redo the
	// outer HMAC layer
	for _, evilChar := range badEncodingCharacters {
		evilString := bytes.Join([][]byte{encrypted[:20], []byte{evilChar}, encrypted[21:]}, []byte{})
		assertNotVerified(t, encryptor, []byte(evilString))
	}
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_encryptor_test.rb#L86
func TestAEADModeEncryption(t *testing.T) {
	_, _, data, secret := setupME(t)

	encryptor := NewMessageEncryptor(secret, secret, EncryptionCipherAES256GCM)
	message, err := encryptor.EncryptAndSign(data, nil, nil)
	assert.Nil(t, err)

	original, err := encryptor.DecryptAndVerify(message, nil)
	assert.Nil(t, err)

	assert.Equal(t, data, original)
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_encryptor_test.rb#L92
func TestAEADModeWithHMACCBCCipherText(t *testing.T) {
	// rails didn't use the fixed secret, so this was never going to test the right thing
	// instead, let's validate that the old works and the new doesn't verify it.
	secret, err := hex.DecodeString("3942b1bf81e622559ed509e3ff274a780784fe9e75b065866bd270438c74da822219de3156473cc27df1fd590e4baf68c95eeb537b6e4d4c5a10f41635b5597e")
	assert.Nil(t, err)

	oldMessage := []byte("eHdGeExnZEwvMSt3U3dKaFl1WFo0TjVvYzA0eGpjbm5WSkt5MXlsNzhpZ0ZnbWhBWFlQZTRwaXE1bVJCS2oxMDZhYVp2dVN3V0lNZUlWQ3c2eVhQbnhnVjFmeVVubmhRKzF3WnZyWHVNMDg9LS1HSisyakJVSFlPb05ISzRMaXRzcFdBPT0=--831a1d54a3cda8a0658dc668a03dedcbce13b5ca")
	expectedPlaintext, err := hex.DecodeString("04087b073a09736f6d6549220964617461063a0645543a086e6f7749753a0954696d650d28801b8000000000073a0b6f666673657469fe808f3a097a6f6e65492208505354063b0646")

	// for completeness, verify that the message is valid
	oldEncryptor := NewMessageEncryptor(secret[:32], secret, EncryptionCipherAES256CBC)
	oldResult, err := oldEncryptor.DecryptAndVerify(oldMessage, nil)
	assert.Nil(t, err)
	assert.Equal(t, expectedPlaintext, oldResult)

	// and now validate the _same_ against the GCM one
	encryptor := NewMessageEncryptor(secret[:32], secret, EncryptionCipherAES256GCM)
	assertAEADDecryptionFails(t, encryptor, oldMessage)
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_encryptor_test.rb#L98
func TestMessingWithAEADValuesCausesFailures(t *testing.T) {
	_, _, data, secret := setupME(t)

	encryptor := NewMessageEncryptor(secret, secret, EncryptionCipherAES256GCM)
	encrypted, err := encryptor.EncryptAndSign(data, nil, nil)
	assert.Nil(t, err)

	parts := bytes.Split(encrypted, []byte("--"))
	assert.Equal(t, 3, len(parts))
	text := parts[0]
	iv := parts[1]
	authTag := parts[2]

	assertAEADDecryptionFails(t, encryptor, bytes.Join([][]byte{iv, text, authTag}, []byte("--")))
	assertAEADDecryptionFails(t, encryptor, bytes.Join([][]byte{munge(text), iv, authTag}, []byte("--")))
	assertAEADDecryptionFails(t, encryptor, bytes.Join([][]byte{text, munge(iv), authTag}, []byte("--")))
	assertAEADDecryptionFails(t, encryptor, bytes.Join([][]byte{text, iv, munge(authTag)}, []byte("--")))
	assertAEADDecryptionFails(t, encryptor, bytes.Join([][]byte{munge(text), munge(iv), munge(authTag)}, []byte("--")))
	assertAEADDecryptionFails(t, encryptor, bytes.Join([][]byte{text, iv}, []byte("--")))
	assertAEADDecryptionFails(t, encryptor, bytes.Join([][]byte{text, iv, authTag[0 : len(authTag)-2]}, []byte("--")))

	// rails did authTag[0:-2] which truncates the base64, what we really want is to truncate the tag itself
	authTagRaw, err := base64.StdEncoding.Strict().DecodeString(string(authTag))
	assert.Nil(t, err)
	truncatedAuthTag := []byte(base64.StdEncoding.Strict().EncodeToString(authTagRaw[0 : len(authTagRaw)-2]))
	assertAEADDecryptionFails(t, encryptor, bytes.Join([][]byte{text, iv, truncatedAuthTag}, []byte("--")))
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_encryptor_test.rb#L110
func TestBackwardsCompatibilityDecryptPreviouslyEncryptedMessagesWithoutMetadata(t *testing.T) {
	secret := []byte("\xB7\xF0\xBCW\xB1\x18`\xAB\xF0\x81\x10\xA4$\xF44\xEC\xA1\xDC\xC1\xDDD\xAF\xA9\xB8\x14\xCD\x18\x9A\x99 \x80)")
	encryptor := NewMessageEncryptor(secret, secret, EncryptionCipherAES256GCM)
	encryptedMessage := []byte("9cVnFs2O3lL9SPvIJuxBOLS51nDiBMw=--YNI5HAfHEmZ7VDpl--ddFJ6tXA0iH+XGcCgMINYQ==")

	original, err := encryptor.DecryptAndVerify(encryptedMessage, nil)
	assert.Nil(t, err)
	// this is in Ruby Marshal format, we only allow raw bytes here so just test the expected raw data
	assert.Equal(t, []byte("\x04\x08I\"\x12Ruby on Rails\x06:\x06ET"), original)
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_encryptor_test.rb#L118
func TestRotatingAEADSecret(t *testing.T) {
	oldSecret := generateSecret(t)
	newSecret := generateSecret(t)

	oldEncryptor := NewMessageEncryptor(oldSecret, oldSecret, EncryptionCipherAES256GCM)
	newEncryptor := NewMessageEncryptor(newSecret, newSecret, EncryptionCipherAES256GCM)

	oldMessage, err := oldEncryptor.EncryptAndSign([]byte("old"), nil, nil)
	assert.Nil(t, err)

	encryptor := NewRotatingMessageEncryptor(newEncryptor, oldEncryptor)

	original, err := encryptor.DecryptAndVerify(oldMessage, nil)
	assert.Nil(t, err)
	assert.Equal(t, []byte("old"), original)
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_encryptor_test.rb#L127
// tests rotating serializers, but this isn't supported here.

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_encryptor_test.rb#L137
func TestRotatingAESCBCSecrets(t *testing.T) {
	oldSecret := generateSecret(t)
	newSecret := generateSecret(t)

	oldEncryptor := NewMessageEncryptor(oldSecret, []byte("old sign"), EncryptionCipherAES256CBC)
	newEncryptor := NewMessageEncryptor(newSecret, newSecret, EncryptionCipherAES256CBC)

	oldMessage, err := oldEncryptor.EncryptAndSign([]byte("old"), nil, nil)
	assert.Nil(t, err)

	encryptor := NewRotatingMessageEncryptor(newEncryptor, oldEncryptor)

	original, err := encryptor.DecryptAndVerify(oldMessage, nil)
	assert.Nil(t, err)
	assert.Equal(t, []byte("old"), original)
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_encryptor_test.rb#L147
func TestMultipleEncryptorRotations(t *testing.T) {
	olderSecret := generateSecret(t)
	oldSecret := generateSecret(t)
	newSecret := generateSecret(t)

	olderEncryptor := NewMessageEncryptor(olderSecret, []byte("older sign"), EncryptionCipherAES256CBC)
	oldEncryptor := NewMessageEncryptor(oldSecret, []byte("old sign"), EncryptionCipherAES256CBC)
	newEncryptor := NewMessageEncryptor(newSecret, newSecret, EncryptionCipherAES256CBC)

	olderMessage, err := olderEncryptor.EncryptAndSign([]byte("older"), nil, nil)
	assert.Nil(t, err)

	oldMessage, err := oldEncryptor.EncryptAndSign([]byte("old"), nil, nil)
	assert.Nil(t, err)

	newMessage, err := newEncryptor.EncryptAndSign([]byte("new"), nil, nil)
	assert.Nil(t, err)

	encryptor := NewRotatingMessageEncryptor(newEncryptor, oldEncryptor, olderEncryptor)

	original, err := encryptor.DecryptAndVerify(newMessage, nil)
	assert.Nil(t, err)
	assert.Equal(t, []byte("new"), original)

	original, err = encryptor.DecryptAndVerify(oldMessage, nil)
	assert.Nil(t, err)
	assert.Equal(t, []byte("old"), original)

	original, err = encryptor.DecryptAndVerify(olderMessage, nil)
	assert.Nil(t, err)
	assert.Equal(t, []byte("older"), original)

	// and finally, ensure that the newest one encrypts
	someMessage, err := encryptor.EncryptAndSign([]byte("one of them"), nil, nil)
	// by verifying that the new one can decrypt the rotated one
	original, err = newEncryptor.DecryptAndVerify(someMessage, nil)
	assert.Nil(t, err)
	assert.Equal(t, []byte("one of them"), original)
}

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_encryptor_test.rb#L160
// we don't support the on_rotation callback

// https://github.com/rails/rails/blob/v5.2.3/activesupport/test/message_encryptor_test.rb#L174
func TestWithRotatedMetadata(t *testing.T) {
	oldSecret := generateSecret(t)
	newSecret := generateSecret(t)

	oldEncryptor := NewMessageEncryptor(oldSecret, oldSecret, EncryptionCipherAES256GCM)
	oldPurpose := "rotation"
	oldMessage, err := oldEncryptor.EncryptAndSign([]byte("metadata"), &oldPurpose, nil)
	assert.Nil(t, err)

	newEncryptor := NewMessageEncryptor(newSecret, newSecret, EncryptionCipherAES256GCM)

	encryptor := NewRotatingMessageEncryptor(newEncryptor, oldEncryptor)

	// with the new encryptor directly should fail
	original, err := newEncryptor.DecryptAndVerify(oldMessage, &oldPurpose)
	assert.NotNil(t, err)

	// with the old encryptor should succeed
	original, err = oldEncryptor.DecryptAndVerify(oldMessage, &oldPurpose)
	assert.Nil(t, err)
	assert.Equal(t, []byte("metadata"), original)

	// with the rotating encryptor should suceed
	original, err = encryptor.DecryptAndVerify(oldMessage, &oldPurpose)
	assert.Nil(t, err)
	assert.Equal(t, []byte("metadata"), original)

	// with the wrong purpose should fail
	original, err = encryptor.DecryptAndVerify(oldMessage, nil)
	assert.NotNil(t, err)
}

// Ensure if we specify a purpose at verify time but didn't encode with one, we reject it
func TestNoMetadataVerifyWithPurpose(t *testing.T) {
	secret := generateSecret(t)

	encryptor := NewMessageEncryptor(secret, secret, EncryptionCipherAES256GCM)
	message, err := encryptor.EncryptAndSign([]byte("no metadata"), nil, nil)
	assert.Nil(t, err)

	// with no purpose should succeed
	original, err := encryptor.DecryptAndVerify(message, nil)
	assert.Nil(t, err)
	assert.Equal(t, []byte("no metadata"), original)

	// with any purpose should fail
	purpose := "testing"
	original, err = encryptor.DecryptAndVerify(message, &purpose)
	assert.NotNil(t, err)
}

// Validate that the encryptor handles extra or too few components correctly in GCM mode
func TestWrongNumberOfComponentsGCM(t *testing.T) {
	_, _, data, secret := setupME(t)

	encryptor := NewMessageEncryptor(secret, secret, EncryptionCipherAES256GCM)
	encrypted, err := encryptor.EncryptAndSign(data, nil, nil)
	assert.Nil(t, err)

	parts := bytes.Split(encrypted, []byte("--"))
	assert.Equal(t, 3, len(parts))
	text := parts[0]
	iv := parts[1]
	authTag := parts[2]

	assertAEADDecryptionFails(t, encryptor, bytes.Join([][]byte{iv, text}, []byte("--")))
	assertAEADDecryptionFails(t, encryptor, bytes.Join([][]byte{iv, text, authTag, authTag}, []byte("--")))
}

// Validate that the encryptor handles extra or too few components correctly in CBC mode
func TestWrongNumberOfComponentsCBC(t *testing.T) {
	verifier, _, data, secret := setupME(t)

	encryptor := NewMessageEncryptor(secret, secret, EncryptionCipherAES256CBC)
	encryptedAndVerified, err := encryptor.EncryptAndSign(data, nil, nil)
	assert.Nil(t, err)

	parts := bytes.Split(encryptedAndVerified, []byte("--"))
	assert.Equal(t, 2, len(parts))
	message := parts[0]
	hmac := parts[1]

	assertNotVerified(t, encryptor, message)
	assertNotVerified(t, encryptor, bytes.Join([][]byte{message, hmac, hmac}, []byte("--")))

	// we also need to bypass the verifier and mess with the underlying encryption
	encrypted, err := verifier.Verify(encryptedAndVerified, nil)
	assert.Nil(t, err)

	parts = bytes.Split(encrypted, []byte("--"))
	assert.Equal(t, 2, len(parts))
	ciphertext := parts[0]
	iv := parts[1]

	// these re-verify, but with the underlying encryption messed with
	assertDecryptionFails(t, verifier, encryptor, ciphertext, "expected 2 components")
	assertDecryptionFails(t, verifier, encryptor, bytes.Join([][]byte{message, iv, iv}, []byte("--")), "expected 2 components")
}

// Key length helper turns a cipher into length
func TestGetMessageEncryptorKeyLength(t *testing.T) {
	assert.Equal(t, 32, GetMessageEncryptorKeyLength(EncryptionCipherAES256GCM))
	assert.Equal(t, 32, GetMessageEncryptorKeyLength(EncryptionCipherAES256CBC))
	assert.Equal(t, 0, GetMessageEncryptorKeyLength("garbage"))
}

func assertDecryptionFails(t *testing.T, verifier MessageVerifier, encryptor MessageEncryptor, msg []byte, expectedMessage string) {
	verified, err := verifier.Generate(msg)
	assert.Nil(t, err)
	result, err := encryptor.DecryptAndVerify(verified, nil)
	assert.NotNil(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), expectedMessage)
	}
	assert.Nil(t, result)
}

func assertDecryptsToInvalid(t *testing.T, verifier MessageVerifier, encryptor MessageEncryptor, msg []byte, validData []byte) {
	verified, err := verifier.Generate(msg)
	assert.Nil(t, err)
	result, err := encryptor.DecryptAndVerify(verified, nil)
	assert.Nil(t, err)
	assert.NotEqual(t, result, validData)
}

func assertAEADDecryptionFails(t *testing.T, encryptor MessageEncryptor, msg []byte) {
	_, err := encryptor.DecryptAndVerify(msg, nil)
	assert.NotNil(t, err)
}

func assertNotVerified(t *testing.T, encryptor MessageEncryptor, msg []byte) {
	result, err := encryptor.DecryptAndVerify(msg, nil)
	assert.NotNil(t, err)
	assert.Nil(t, result)
}

func munge(enc []byte) []byte {
	bytes, err := base64.StdEncoding.Strict().DecodeString(string(enc))
	if err != nil {
		panic(err)
	}
	bytes = reverse(bytes)
	return []byte(base64.StdEncoding.Strict().EncodeToString(bytes))
}

func generateSecret(t *testing.T) []byte {
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	assert.Nil(t, err)

	return secret
}
