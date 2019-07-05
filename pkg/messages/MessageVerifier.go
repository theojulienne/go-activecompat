package messages

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"time"
)

// MessageVerifier is a Go version of ActiveSupport::MessageVerifier, designed to mimick that API as closely as possible
type MessageVerifier interface {
	IsValidMessage(signedMessage []byte) bool
	Verify(signedMessage []byte, purpose *string) ([]byte, error)
	Generate(rawMessage []byte) ([]byte, error)
	GenerateWithMetadata(rawMessage []byte, purpose *string, expiresAt *time.Time) ([]byte, error)
}

// MessageVerifierSHA1 implements MessageVerifier and verifies messages with SHA1
type MessageVerifierHash struct {
	secret []byte
	digest func() hash.Hash
}

func NewMessageVerifier(secret []byte, digest func() hash.Hash) *MessageVerifierHash {
	if secret == nil {
		return nil
	}

	return &MessageVerifierHash{
		secret: secret,
		digest: digest,
	}
}

func NewMessageVerifierSHA1(secret []byte) *MessageVerifierHash {
	return NewMessageVerifier(secret, sha1.New)
}

func NewMessageVerifierSHA256(secret []byte) *MessageVerifierHash {
	return NewMessageVerifier(secret, sha256.New)
}

func NewMessageVerifierSHA512(secret []byte) *MessageVerifierHash {
	return NewMessageVerifier(secret, sha512.New)
}

func (mv *MessageVerifierHash) IsValidMessage(signedMessage []byte) bool {
	parts := bytes.Split(signedMessage, []byte("--"))
	if len(parts) != 2 {
		return false
	}

	data := parts[0]
	digestHex := parts[1]

	digestRaw, err := hex.DecodeString(string(digestHex))
	if err != nil {
		return false
	}

	// aims to match the below https://github.com/rails/rails/blob/v5.2.3/activesupport/lib/active_support/message_verifier.rb#L126
	// ActiveSupport::SecurityUtils.secure_compare(digest, generate_digest(data))
	return hmac.Equal(digestRaw, mv.generateDigest(data))
}

func (mv *MessageVerifierHash) Verify(signedMessage []byte, purpose *string) ([]byte, error) {
	if mv.IsValidMessage(signedMessage) {
		parts := bytes.Split(signedMessage, []byte("--"))
		if len(parts) != 2 {
			return nil, errors.New("message should have been in 2 parts")
		}

		dataB64 := parts[0]

		// decode the base64, since it's wrapped in decode()
		// see: https://github.com/rails/rails/blob/v5.2.3/activesupport/lib/active_support/message_verifier.rb#L154
		data, err := base64.StdEncoding.Strict().DecodeString(string(dataB64))
		if err != nil {
			return nil, err
		}

		// pass along the purpose, metadata validates that
		// see: https://github.com/rails/rails/blob/v5.2.3/activesupport/lib/active_support/message_verifier.rb#L154
		message, err := VerifyMessageMetadataWithPurpose(data, purpose)
		return message, err
	}

	return nil, errors.New("message was not valid")
}

func (mv *MessageVerifierHash) Generate(rawMessage []byte) ([]byte, error) {
	// match the encode() base64 wrapping
	// see: https://github.com/rails/rails/blob/v5.2.3/activesupport/lib/active_support/message_verifier.rb#L187
	data := []byte(base64.StdEncoding.Strict().EncodeToString(rawMessage))

	// we digest and hex the base64 version above, same as `generate_digest(data)`
	digestHex := []byte(hex.EncodeToString(mv.generateDigest(data)))

	// matches "#{data}--#{generate_digest(data)}"
	// see: https://github.com/rails/rails/blob/v5.2.3/activesupport/lib/active_support/message_verifier.rb#L187-L188
	return bytes.Join([][]byte{data, digestHex}, []byte("--")), nil
}

func (mv *MessageVerifierHash) GenerateWithMetadata(rawMessage []byte, purpose *string, expiresAt *time.Time) ([]byte, error) {
	dataRaw, err := WrapMessageWithMetadata(rawMessage, purpose, expiresAt)
	if err != nil {
		return nil, err
	}

	bytes, err := mv.Generate(dataRaw)
	return bytes, err
}

func (mv *MessageVerifierHash) generateDigest(rawMessage []byte) []byte {
	signer := hmac.New(mv.digest, mv.secret)
	signer.Write(rawMessage)
	return signer.Sum(nil)
}

// MessageVerifierNull implements MessageVerifier and accepts every message
type MessageVerifierNull struct {
}

func NewMessageVerifierNull() *MessageVerifierNull {
	return &MessageVerifierNull{}
}

func (mv *MessageVerifierNull) IsValidMessage(signedMessage []byte) bool {
	return true
}

func (mv *MessageVerifierNull) Verify(signedMessage []byte, purpose *string) ([]byte, error) {
	return signedMessage, nil
}

func (mv *MessageVerifierNull) Generate(rawMessage []byte) ([]byte, error) {
	return rawMessage, nil
}

func (mv *MessageVerifierNull) GenerateWithMetadata(rawMessage []byte, purpose *string, expiresAt *time.Time) ([]byte, error) {
	return rawMessage, nil
}

// RotatingMessageVerifier implements the rotation from ActiveSupport::MessageVerifier
type RotatingMessageVerifier struct {
	verifiers []MessageVerifier
}

func NewRotatingMessageVerifier(verifiers ...MessageVerifier) MessageVerifier {
	for _, verifier := range verifiers {
		if verifier == nil {
			// this isn't valid
			return nil
		}
	}

	return &RotatingMessageVerifier{
		verifiers: verifiers,
	}
}

func (mv *RotatingMessageVerifier) IsValidMessage(signedMessage []byte) bool {
	for _, verifier := range mv.verifiers {
		if verifier.IsValidMessage(signedMessage) {
			return true
		}
	}
	return false
}

func (mv *RotatingMessageVerifier) Verify(signedMessage []byte, purpose *string) ([]byte, error) {
	var firstErr error
	for _, verifier := range mv.verifiers {
		verified, err := verifier.Verify(signedMessage, purpose)
		if err == nil && verified != nil {
			return verified, err
		}
		if err != nil && firstErr == nil {
			// save the first error, we'll return that one
			firstErr = err
		}
	}
	return nil, firstErr
}

func (mv *RotatingMessageVerifier) Generate(rawMessage []byte) ([]byte, error) {
	// always use the newest/first one, that's the one we want to move to
	return mv.verifiers[0].Generate(rawMessage)
}

func (mv *RotatingMessageVerifier) GenerateWithMetadata(rawMessage []byte, purpose *string, expiresAt *time.Time) ([]byte, error) {
	// always use the newest/first one, that's the one we want to move to
	return mv.verifiers[0].GenerateWithMetadata(rawMessage, purpose, expiresAt)
}
