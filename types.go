package certmagic_vault_storage

import (
	"encoding/json"
	"net/url"
	"strings"
	"time"
)

type Time time.Time

func (t *Time) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Time(*t).Format(time.RFC3339Nano) + `"`), nil
}

func (t *Time) UnmarshalJSON(data []byte) error {
	value := strings.Trim(string(data), "\"")
	if value != "" {
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return err
		}

		*t = Time(parsed)
	}

	return nil
}

type Duration time.Duration

func (d *Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Duration(*d).String() + `"`), nil
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	value := strings.Trim(string(data), "\"")
	if value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return err
		}

		*d = Duration(parsed)
	}

	return nil
}

func MustParseURL(rawUrl string) *URL {
	parsedUrl, _ := ParseURL(rawUrl)
	return parsedUrl
}

func ParseURL(rawUrl string) (*URL, error) {
	parsedUrl, err := url.Parse(rawUrl)
	if err != nil {
		return nil, err
	}

	return &URL{parsedUrl}, nil
}

type URL struct {
	*url.URL
}

func (u *URL) MarshalJSON() ([]byte, error) {
	return []byte(`"` + u.String() + `"`), nil
}

func (u *URL) UnmarshalJSON(data []byte) error {
	var err error
	var rawUrl string
	var parsedUrl *url.URL

	err = json.Unmarshal(data, &rawUrl)
	if err != nil {
		return err
	}

	parsedUrl, err = url.Parse(rawUrl)
	if err != nil {
		return err
	}
	u.URL = parsedUrl

	return nil
}
