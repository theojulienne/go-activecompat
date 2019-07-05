package messages

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type railsEncodedMetadataMessage struct {
	Message   string     `json:"message"`
	ExpiresAt *time.Time `json:"exp"`
	Purpose   *string    `json:"pur"`
}

type railsEncodedMetadata struct {
	Metadata *railsEncodedMetadataMessage `json:"_rails"`
}

// VerifyMessageMetadataWithPurpose matches the behaviour of ActiveSupport::Messages::Metadata.verify
func VerifyMessageMetadataWithPurpose(message []byte, purpose *string) ([]byte, error) {
	var outer railsEncodedMetadata
	err := json.Unmarshal(message, &outer)
	if err != nil || outer.Metadata == nil {
		// this is not json, or not in the valid metadata format, so bail.
		// in rails, the lack of valid metadata struct indicates the purpose must be nil
		// see: https://github.com/rails/rails/blob/v5.2.3/activesupport/lib/active_support/messages/metadata.rb#L41
		if purpose == nil {
			return message, nil
		} else {
			// otherwise, if a purpose is specified, then we don't match because we didn't explicitly have that purpose
			return nil, errors.New("purpose specified but metadata not provided")
		}
	}

	// check that the purpose matches
	if !purposesMatch(purpose, outer.Metadata.Purpose) {
		return nil, errors.New(fmt.Sprintf("purpose did not match, expected '%s' but metadata contained '%s'", stringOrNil(purpose), stringOrNil(outer.Metadata.Purpose)))
	}

	// check if stale
	if outer.Metadata.ExpiresAt != nil && outer.Metadata.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("metadata indicates message has expired")
	}

	// the message is base64 encoded, so decode. StdEncoding is RFC 4648, which matches ruby
	// see: https://github.com/rails/rails/blob/v5.2.3/activesupport/lib/active_support/messages/metadata.rb#L42
	// see: https://apidock.com/ruby/Base64/strict_decode64
	rawMessage, _ := base64.StdEncoding.Strict().DecodeString(outer.Metadata.Message)
	return rawMessage, nil
}

func WrapMessageWithMetadata(rawMessage []byte, purpose *string, expiresAt *time.Time) ([]byte, error) {
	if purpose == nil && expiresAt == nil {
		// if we specify neither of these, we don't wrap it
		// see: https://github.com/rails/rails/blob/v5.2.3/activesupport/lib/active_support/messages/metadata.rb#L18-L22
		return rawMessage, nil
	}

	outer := railsEncodedMetadata{
		Metadata: &railsEncodedMetadataMessage{
			Message:   base64.StdEncoding.Strict().EncodeToString(rawMessage),
			Purpose:   purpose,
			ExpiresAt: expiresAt,
		},
	}

	bytes, err := json.Marshal(outer)
	return bytes, err
}

func stringOrNil(s *string) string {
	if s == nil {
		return "<nil>"
	} else {
		return *s
	}
}

func purposesMatch(a *string, b *string) bool {
	// if either is nil, both must be nil
	if a == nil || b == nil {
		return (a == nil && b == nil)
	}
	// otherwise, both are set, and must match
	return (*a == *b)
}
