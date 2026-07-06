package mtglib

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEffectiveAdTag(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	bob := GenerateSecret("bob.example.com")

	global := [AdTagLength]byte{0xff}
	perBob := [AdTagLength]byte{0xbb}

	set := buildSecretSet(
		map[string]Secret{"alice": alice, "bob": bob},
		map[string][AdTagLength]byte{"bob": perBob},
		&global,
	)

	// names are sorted: alice=0, bob=1.
	require.Equal(t, []string{"alice", "bob"}, set.names)

	// alice has no override -> falls back to the global tag.
	require.NotNil(t, set.effectiveAdTag(0))
	assert.Equal(t, global, *set.effectiveAdTag(0))

	// bob has an override -> its own tag wins.
	require.NotNil(t, set.effectiveAdTag(1))
	assert.Equal(t, perBob, *set.effectiveAdTag(1))
}

func TestEffectiveAdTagNoGlobal(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")

	set := buildSecretSet(map[string]Secret{"alice": alice}, nil, nil)

	// No override and no global tag -> nil (the direct-DC path).
	assert.Nil(t, set.effectiveAdTag(0))
}

func TestReloadKeepsAdTags(t *testing.T) {
	t.Parallel()

	alice := GenerateSecret("alice.example.com")
	global := [AdTagLength]byte{0x11}

	p := newReloadTestProxy(map[string]Secret{"alice": alice})
	p.reloader = func() (SecretConfig, error) {
		return SecretConfig{
			Secrets:     map[string]Secret{"alice": alice},
			GlobalAdTag: &global,
		}, nil
	}

	require.NoError(t, p.ReloadSecrets())
	require.NotNil(t, p.secrets.Load().globalAdTag)
	assert.Equal(t, global, *p.secrets.Load().globalAdTag)
}
