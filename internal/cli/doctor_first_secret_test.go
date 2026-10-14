package cli

import (
	"testing"

	"github.com/mhsanaei/mtg-multi/internal/config"
	"github.com/mhsanaei/mtg-multi/mtglib"
	"github.com/stretchr/testify/require"
)

// TestDoctorFirstSecretHostIsDeterministic guards against ranging over the
// secrets map: with several secrets the doctor must always check the same one
// (lexicographically first by name), not whichever the runtime iterates first.
func TestDoctorFirstSecretHostIsDeterministic(t *testing.T) {
	conf := &config.Config{
		Secrets: map[string]mtglib.Secret{
			"charlie": {Host: "c.example"},
			"alpha":   {Host: "a.example"},
			"bravo":   {Host: "b.example"},
		},
	}
	d := &Doctor{conf: conf}

	for range 200 {
		require.Equal(t, "a.example", d.getFirstSecretHost())
	}
}

func TestDoctorFirstSecretHostSingleSecret(t *testing.T) {
	conf := &config.Config{}
	conf.Secret.Host = "only.example"
	d := &Doctor{conf: conf}

	require.Equal(t, "only.example", d.getFirstSecretHost())
}

func TestDoctorFirstSecretHostNoHost(t *testing.T) {
	d := &Doctor{conf: &config.Config{}}

	require.Equal(t, "", d.getFirstSecretHost())
}
