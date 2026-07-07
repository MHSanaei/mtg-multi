package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/mhsanaei/mtg-multi/mtglib"
)

// Environment variable names understood by ApplyEnvironment. The unprefixed
// names mirror the official telegrammessenger/proxy Docker image
// (https://hub.docker.com/r/telegrammessenger/proxy/), so its documented
// "docker run -e SECRET=... -e TAG=..." invocations work with mtg-multi
// containers as well. MTG_-prefixed variants always win over the unprefixed
// ones, so generic names like SECRET cannot be captured by accident outside
// of a container.
const (
	// EnvSecret is the proxy secret. Either a full mtg secret (ee-prefixed
	// hex or base64) or, for parity with the official image, a bare 16-byte
	// hex key which is combined with EnvSecretHost into a FakeTLS secret.
	EnvSecret = "SECRET"

	// EnvSecretHost is the domain-fronting hostname used when EnvSecret
	// holds a bare 16-byte key. Ignored when EnvSecret is a full secret.
	EnvSecretHost = "SECRET_HOST"

	// EnvAdTag is the advertising tag issued by @MTProxybot (the official
	// image calls it TAG). An empty value clears the tag from the file.
	EnvAdTag = "TAG"

	// EnvBindTo is a comma-separated list of host:port pairs to listen on.
	// It has no unprefixed form: the official image does not document one.
	EnvBindTo = "MTG_BIND_TO"

	envPrefix = "MTG_"
)

// lookupEnv reads the MTG_-prefixed variant of name first and falls back to
// the bare official-image name.
func lookupEnv(name string) (string, bool) {
	if value, ok := os.LookupEnv(envPrefix + name); ok {
		return value, true
	}

	return os.LookupEnv(name)
}

// ApplyEnvironment overlays environment variables on top of a parsed config
// file. The environment always wins, mirroring how the official
// telegrammessenger/proxy image is configured per "docker run". It is applied
// on every config read, including hot reloads, so an env-pinned secret or tag
// survives a POST /reload.
func (c *Config) ApplyEnvironment() error {
	if err := c.applyEnvSecret(); err != nil {
		return err
	}

	if err := c.applyEnvAdTag(); err != nil {
		return err
	}

	return c.applyEnvBindTo()
}

func (c *Config) applyEnvSecret() error {
	value, ok := lookupEnv(EnvSecret)
	if !ok {
		return nil
	}

	secret, err := parseEnvSecret(strings.TrimSpace(value))
	if err != nil {
		return err
	}

	// The environment fully defines the secret set: named [secrets] and
	// their [secret-ad-tags] from the file no longer apply.
	c.Secret = secret
	c.Secrets = nil
	c.SecretAdTags = nil

	return nil
}

func parseEnvSecret(value string) (mtglib.Secret, error) {
	// The official telegrammessenger/proxy image uses bare 16-byte hex
	// secrets. mtg serves FakeTLS only, so such a key needs a fronting
	// hostname to become an ee-secret. A full serialized secret is always
	// longer than 16 bytes, so this branch cannot swallow one.
	if raw, err := hex.DecodeString(value); err == nil && len(raw) == mtglib.SecretKeyLength {
		host, _ := lookupEnv(EnvSecretHost)
		if host = strings.TrimSpace(host); host == "" {
			return mtglib.Secret{}, fmt.Errorf(
				"%s is a bare 16-byte key (telegrammessenger/proxy format); mtg serves FakeTLS only, "+
					"so either set %s to a fronting domain or provide a full ee-prefixed secret", EnvSecret, EnvSecretHost)
		}

		secret := mtglib.Secret{Host: host}
		copy(secret.Key[:], raw)

		return secret, nil
	}

	secret, err := mtglib.ParseSecret(value)
	if err != nil {
		return mtglib.Secret{}, fmt.Errorf("incorrect %s environment variable: %w", EnvSecret, err)
	}

	return secret, nil
}

func (c *Config) applyEnvAdTag() error {
	value, ok := lookupEnv(EnvAdTag)
	if !ok {
		return nil
	}

	if err := c.AdTag.Set(strings.TrimSpace(value)); err != nil {
		return fmt.Errorf("incorrect %s environment variable: %w", EnvAdTag, err)
	}

	return nil
}

func (c *Config) applyEnvBindTo() error {
	value, ok := os.LookupEnv(EnvBindTo)
	if !ok {
		return nil
	}

	parts := strings.Split(value, ",")
	binds := make([]TypeHostPort, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		hp := TypeHostPort{}
		if err := hp.Set(part); err != nil {
			return fmt.Errorf("incorrect %s environment variable: %w", EnvBindTo, err)
		}

		binds = append(binds, hp)
	}

	if len(binds) == 0 {
		return fmt.Errorf("%s must contain at least one host:port", EnvBindTo)
	}

	c.BindTo = binds

	return nil
}
