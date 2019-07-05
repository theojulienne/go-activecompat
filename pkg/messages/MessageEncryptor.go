package messages

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/enceve/crypto/pad"
)

// MessageEncryptor is a Go version of ActiveSupport::MessageEncryptor, designed to mimick that API as closely as possible
type MessageEncryptor interface {
	EncryptAndSign(message []byte, purpose *string, expiresAt *time.Time) ([]byte, error)
	DecryptAndVerify(encrypted []byte, purpose *string) ([]byte, error)
}

// RotatingMessageEncryptor implements the rotation from ActiveSupport::MessageEncryptor
type RotatingMessageEncryptor struct {
	encryptors []MessageEncryptor
}

func NewRotatingMessageEncryptor(encryptors ...MessageEncryptor) MessageEncryptor {
	return &RotatingMessageEncryptor{
		encryptors: encryptors,
	}
}

func (me *RotatingMessageEncryptor) EncryptAndSign(message []byte, purpose *string, expiresAt *time.Time) ([]byte, error) {
	// always encrypts with the first encryptor, since it's the desired one
	return me.encryptors[0].EncryptAndSign(message, purpose, expiresAt)
}

func (me *RotatingMessageEncryptor) DecryptAndVerify(encrypted []byte, purpose *string) ([]byte, error) {
	var firstErr error
	for _, encryptor := range me.encryptors {
		result, err := encryptor.DecryptAndVerify(encrypted, purpose)
		if err == nil {
			return result, nil
		}
		if firstErr == nil {
			// save the first error, so we use the "primary" encryptor's error for return
			firstErr = err
		}
	}
	return nil, firstErr
}

// RailsMessageEncryptor is a rails-compatible implementation of MessageEncryptor which implements ActiveSupport::MessageEncryptor
// except for the rotation.
type RailsMessageEncryptor struct {
	encryptionSecret []byte
	signingSecret    []byte
	cipher           string

	verifier MessageVerifier
}

const (
	EncryptionCipherAES256GCM = "aes-256-gcm"
	EncryptionCipherAES256CBC = "aes-256-cbc"

	// https://github.com/rails/rails/blob/v5.2.3/activesupport/lib/active_support/message_encryptor.rb#L88
	RailsDefaultAuthenticatedMessageEncryptionCipher    = EncryptionCipherAES256GCM
	RailsDefaultNonAuthenticatedMessageEncryptionCipher = EncryptionCipherAES256CBC
)

func NewMessageEncryptor(encryptionSecret []byte, signingSecret []byte, cipher string) MessageEncryptor {
	me := &RailsMessageEncryptor{
		encryptionSecret: encryptionSecret,
		signingSecret:    signingSecret,
		cipher:           cipher,
	}

	switch cipher {
	case EncryptionCipherAES256GCM:
		// GCM is:
		//  "AEAD is a cipher mode providing authenticated encryption with associated data"
		// rails turns off the message verifier when using GCM
		// see: https://github.com/rails/rails/blob/v5.2.3/activesupport/lib/active_support/message_encryptor.rb#L222
		me.verifier = NewMessageVerifierNull()
	case EncryptionCipherAES256CBC:
		// CBC doesn't have verification so we use the SHA1 to match rails
		// see: https://github.com/rails/rails/blob/v5.2.3/activesupport/lib/active_support/message_encryptor.rb#L225
		me.verifier = NewMessageVerifierSHA1(signingSecret)
	default:
		return nil
	}

	return me
}

func GetMessageEncryptorKeyLength(cipher string) int {
	switch cipher {
	case EncryptionCipherAES256GCM, EncryptionCipherAES256CBC:
		return 32
	}
	return 0
}

func (me *RailsMessageEncryptor) EncryptAndSign(message []byte, purpose *string, expiresAt *time.Time) ([]byte, error) {
	// purpose and expiresAt are set on the encryption layer, use the verifier here just for verification
	// see: https://github.com/rails/rails/blob/v5.2.3/activesupport/lib/active_support/message_encryptor.rb#L151
	encryptedBytes, err := me.encrypt(message, purpose, expiresAt)
	if err != nil {
		return nil, err
	}

	bytes, err := me.verifier.Generate(encryptedBytes)
	return bytes, err
}

func (me *RailsMessageEncryptor) DecryptAndVerify(encrypted []byte, purpose *string) ([]byte, error) {
	// _decrypt(verifier.verify(data), purpose)
	// note the verify doesn't have a 'purpose' specified here, that's in the encryption layer
	// see: https://github.com/rails/rails/blob/v5.2.3/activesupport/lib/active_support/message_encryptor.rb#L157
	encryptedBytes, err := me.verifier.Verify(encrypted, nil)
	if err != nil {
		return nil, err
	}

	bytes, err := me.decrypt(encryptedBytes, purpose)
	return bytes, err
}

func (me *RailsMessageEncryptor) encrypt(message []byte, purpose *string, expiresAt *time.Time) ([]byte, error) {
	block, err := aes.NewCipher(me.encryptionSecret)
	if err != nil {
		return nil, err
	}

	plaintext, err := WrapMessageWithMetadata(message, purpose, expiresAt)
	if err != nil {
		return nil, err
	}

	switch me.cipher {
	case EncryptionCipherAES256GCM:
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		// from https://golang.org/pkg/crypto/cipher/#NewGCM
		// the NonceSize is noted as the thing to use in: https://golang.org/pkg/crypto/cipher/#AEAD
		nonce := make([]byte, aesgcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, err
		}

		encryptedAndTag := aesgcm.Seal(nil, nonce, plaintext, nil)

		encryptedData := encryptedAndTag[:len(plaintext)]
		authTag := encryptedAndTag[len(plaintext):]

		// aead mode output:
		// "#{::Base64.strict_encode64 encrypted_data}--#{::Base64.strict_encode64 iv}--#{::Base64.strict_encode64 cipher.auth_tag}"
		// see: https://github.com/rails/rails/blob/v5.2.3/activesupport/lib/active_support/message_encryptor.rb#L179
		return joinAndBase64Bytes(encryptedData, nonce, authTag), nil
	case EncryptionCipherAES256CBC:
		iv := make([]byte, block.BlockSize())
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, err
		}
		mode := cipher.NewCBCEncrypter(block, iv)

		padder := pad.NewPKCS7(block.BlockSize())
		padded := padder.Pad(plaintext)

		encryptedData := make([]byte, len(padded))
		mode.CryptBlocks(encryptedData, padded)

		// non-aead mode output: "#{::Base64.strict_encode64 encrypted_data}--#{::Base64.strict_encode64 iv}"
		// see: https://github.com/rails/rails/blob/v5.2.3/activesupport/lib/active_support/message_encryptor.rb#L178
		return joinAndBase64Bytes(encryptedData, iv), nil
	}

	return nil, errors.New("unxpected cipher")
}

func (me *RailsMessageEncryptor) decrypt(message []byte, purpose *string) ([]byte, error) {
	block, err := aes.NewCipher(me.encryptionSecret)
	if err != nil {
		return nil, err
	}

	components, err := splitAndUnBase64Bytes(message)
	if err != nil {
		return nil, err
	}

	var plaintext []byte

	switch me.cipher {
	case EncryptionCipherAES256GCM:
		if len(components) != 3 {
			return nil, errors.New("expected 3 components in encrypted message, but got 1")
		}

		encryptedData := components[0]
		nonce := components[1]
		authTag := components[2]

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		if len(nonce) != aesgcm.NonceSize() {
			// rails doesn't check this one, but worth being safe
			// see: https://github.com/rails/rails/blob/v5.2.3/activesupport/lib/active_support/message_encryptor.rb#L190
			return nil, errors.New("iv had incorrect length")
		}

		if len(authTag) != 16 { // this is also gcmTagSize, but not exported https://golang.org/src/crypto/cipher/gcm.go
			// match rails checking this length just in case
			// see: https://github.com/rails/rails/blob/v5.2.3/activesupport/lib/active_support/message_encryptor.rb#L190
			return nil, errors.New("authTag had incorrect length")
		}

		// match back to go's concatenated data+authtag
		compatCrypt := append(encryptedData, authTag...)
		plaintext, err = aesgcm.Open(nil, nonce, compatCrypt, nil)
		if err != nil {
			return nil, err
		}

	case EncryptionCipherAES256CBC:
		if len(components) != 2 {
			return nil, errors.New("expected 2 components in encrypted message, but got 1")
		}
		encryptedData := components[0]
		iv := components[1]

		if len(iv) != block.BlockSize() {
			// rails doesn't check this one, but worth being safe
			// see: https://github.com/rails/rails/blob/v5.2.3/activesupport/lib/active_support/message_encryptor.rb#L190
			return nil, errors.New("iv had incorrect length")
		}

		mode := cipher.NewCBCDecrypter(block, iv)
		plaintext = make([]byte, len(encryptedData))
		mode.CryptBlocks(plaintext, encryptedData)

		padder := pad.NewPKCS7(block.BlockSize())
		plaintext, err = padder.Unpad(plaintext)
		if err != nil {
			return nil, err
		}
	}

	unwrapped, err := VerifyMessageMetadataWithPurpose(plaintext, purpose)
	return unwrapped, err
}

func joinAndBase64Bytes(blobs ...[]byte) []byte {
	encodedBlobs := make([]string, len(blobs))
	for i, blob := range blobs {
		encodedBlobs[i] = base64.StdEncoding.Strict().EncodeToString(blob)
	}
	return []byte(strings.Join(encodedBlobs, "--"))
}

func splitAndUnBase64Bytes(data []byte) ([][]byte, error) {
	blobs := strings.Split(string(data), "--")
	decodedBlobs := make([][]byte, len(blobs))
	for i, blob := range blobs {
		bytes, err := base64.StdEncoding.Strict().DecodeString(blob)
		if err != nil {
			return nil, err
		}
		decodedBlobs[i] = bytes
	}
	return decodedBlobs, nil
}
