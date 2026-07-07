package config_test

import (
	"encoding/hex"
	"testing"

	"github.com/mhsanaei/mtg-multi/internal/config"
	"github.com/stretchr/testify/suite"
)

const (
	envTestSecretHex    = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
	envTestSecretBase64 = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"

	// A bare 16-byte key in the format of the official
	// telegrammessenger/proxy image (its Docker Hub example value).
	envTestBareKey = "00baadf00d15abad1deaa515baadcafe"
)

const envTestMultiSecretConfig = `
bind-to = "0.0.0.0:3128"
ad-tag = "0123456789abcdef0123456789abcdef"

[secrets]
alice = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
bob = "7oe1GqLy6TBc38CV3jx7q09nb29nbGUuY29t"

[secret-ad-tags]
bob = "fedcba9876543210fedcba9876543210"
`

// EnvTestSuite mutates process environment via T().Setenv, so its top-level
// test must not run in parallel.
type EnvTestSuite struct {
	suite.Suite
}

func (suite *EnvTestSuite) ParseConfig(text string) *config.Config {
	conf, err := config.Parse([]byte(text))
	suite.Require().NoError(err)

	return conf
}

func (suite *EnvTestSuite) MinimalConfig() *config.Config {
	return suite.ParseConfig("bind-to = \"0.0.0.0:3128\"\nsecret = \"" + envTestSecretBase64 + "\"\n")
}

func (suite *EnvTestSuite) TestNoEnvKeepsConfigUntouched() {
	conf := suite.ParseConfig(envTestMultiSecretConfig)
	suite.NoError(conf.ApplyEnvironment())
	suite.Len(conf.Secrets, 2)
	suite.NotNil(conf.GetAdTag())
	suite.Contains(conf.GetSecretAdTags(), "bob")
}

func (suite *EnvTestSuite) TestSecretOverridesSecretSet() {
	suite.T().Setenv("SECRET", envTestSecretHex)

	conf := suite.ParseConfig(envTestMultiSecretConfig)
	suite.NoError(conf.ApplyEnvironment())
	suite.NoError(conf.Validate())

	suite.Empty(conf.Secrets)
	suite.Nil(conf.GetSecretAdTags())
	suite.Equal(envTestSecretHex, conf.Secret.Hex())
	suite.True(conf.GetSecrets()["default"].Valid())
}

func (suite *EnvTestSuite) TestPrefixedSecretWins() {
	suite.T().Setenv("SECRET", "garbage")
	suite.T().Setenv("MTG_SECRET", envTestSecretBase64)

	conf := suite.MinimalConfig()
	suite.NoError(conf.ApplyEnvironment())
	suite.Equal(envTestSecretBase64, conf.Secret.Base64())
}

func (suite *EnvTestSuite) TestBareKeyNeedsHost() {
	suite.T().Setenv("SECRET", envTestBareKey)

	conf := suite.MinimalConfig()
	suite.ErrorContains(conf.ApplyEnvironment(), "SECRET_HOST")
}

func (suite *EnvTestSuite) TestBareKeyWithHost() {
	suite.T().Setenv("SECRET", envTestBareKey)
	suite.T().Setenv("SECRET_HOST", "storage.googleapis.com")

	conf := suite.MinimalConfig()
	suite.NoError(conf.ApplyEnvironment())
	suite.NoError(conf.Validate())
	suite.Equal("storage.googleapis.com", conf.Secret.Host)
	suite.Equal(envTestBareKey, hex.EncodeToString(conf.Secret.Key[:]))
}

func (suite *EnvTestSuite) TestGarbageSecret() {
	suite.T().Setenv("SECRET", "garbage")

	conf := suite.MinimalConfig()
	suite.Error(conf.ApplyEnvironment())
}

func (suite *EnvTestSuite) TestTagSetsAdTag() {
	suite.T().Setenv("TAG", "fedcba9876543210fedcba9876543210")

	conf := suite.MinimalConfig()
	suite.NoError(conf.ApplyEnvironment())
	suite.Equal("fedcba9876543210fedcba9876543210", conf.AdTag.String())
}

func (suite *EnvTestSuite) TestEmptyTagClearsAdTag() {
	suite.T().Setenv("TAG", "")

	conf := suite.ParseConfig(envTestMultiSecretConfig)
	suite.NoError(conf.ApplyEnvironment())
	suite.Nil(conf.GetAdTag())
}

func (suite *EnvTestSuite) TestBadTag() {
	suite.T().Setenv("TAG", "abcd")

	conf := suite.MinimalConfig()
	suite.Error(conf.ApplyEnvironment())
}

func (suite *EnvTestSuite) TestBindToSingle() {
	suite.T().Setenv("MTG_BIND_TO", "0.0.0.0:443")

	conf := suite.MinimalConfig()
	suite.NoError(conf.ApplyEnvironment())
	suite.Equal([]string{"0.0.0.0:443"}, conf.GetBindAddrs())
}

func (suite *EnvTestSuite) TestBindToMultiple() {
	suite.T().Setenv("MTG_BIND_TO", "127.0.0.1:443, [::1]:443")

	conf := suite.MinimalConfig()
	suite.NoError(conf.ApplyEnvironment())
	suite.Equal([]string{"127.0.0.1:443", "[::1]:443"}, conf.GetBindAddrs())
}

func (suite *EnvTestSuite) TestBindToInvalid() {
	suite.T().Setenv("MTG_BIND_TO", "example.com:443")

	conf := suite.MinimalConfig()
	suite.Error(conf.ApplyEnvironment())
}

func (suite *EnvTestSuite) TestBindToEmpty() {
	suite.T().Setenv("MTG_BIND_TO", " , ")

	conf := suite.MinimalConfig()
	suite.Error(conf.ApplyEnvironment())
}

func TestEnv(t *testing.T) {
	suite.Run(t, &EnvTestSuite{})
}
