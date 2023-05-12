package certmagic_vault_storage

import (
	. "fmt"
	"strings"
)

const (
	// vaultCertMagicCertificateDataPathFormat & vaultCertMagicCertificateMetadataPathFormat formatters are:
	//    1st %s: SecretsPath
	//    2nd %s: PathPrefix
	//    3rd %s: key/prefix
	vaultCertMagicCertificateDataPathFormat     secretPathFormatType = "%s/data/%s/%s"
	vaultCertMagicCertificateMetadataPathFormat secretPathFormatType = "%s/metadata/%s/%s"
)

type secretPathFormatType string

func (f secretPathFormatType) String(args ...interface{}) string {
	return strings.ToLower(Sprintf(string(f), args...))
}

type response struct {
	Data data `json:"data"`
}

type data struct {
	Data     certificateSecret `json:"data"`
	Metadata metadata          `json:"metadata"`
}

type certificateSecret struct {
	Certmagic certMagicCertificateSecret `json:"certmagic"`
}

type certMagicCertificateSecret struct {
	Data []byte `json:"data,omitempty"`
	Lock *Time  `json:"lock,omitempty"`
}

type metadata struct {
	Destroyed    bool `json:"destroyed"`
	CreatedTime  Time `json:"created_time"`
	DeletionTime Time `json:"deletion_time"`
}

type listResponse struct {
	Data listResponseData `json:"data"`
}

type listResponseData struct {
	Keys []string `json:"keys"`
}
