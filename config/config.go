package config

import (
	"io/ioutil"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Analytics   analytics         `toml:"analytics"`
	S3          s3Config          `toml:"s3"`
	Persistence persistenceConfig `toml:"persistence"`
	Results     resultsConfig     `toml:"results"`
	Proxy       resultsConfig     `toml:"proxy"`
	General     generalConfig     `toml:"general"`
	Endpoints   endpointsConfig   `toml:"endpoints"`
}

type analytics struct {
	GAID string `toml:"ga_id"` // Google Analytics ID
}

type s3Config struct {
	Upload        bool   `toml:"upload"`
	Region        string `toml:"region"`
	Endpoint      string `toml:"endpoint"`
	PrivateBucket string `toml:"private_bucket"`
	PublicBucket  string `toml:"public_bucket"`
}

type persistenceConfig struct {
	Endpoint string `toml:"endpoint"`
}

type resultsConfig struct {
	Endpoint string `toml:"endpoint"`
}

type proxy struct {
	Endpoint string `toml:"endpoint"`
}

type generalConfig struct {
	ResourcesPath     string `toml:"resources_path"`
	LocalTempDir      string `toml:"local_temp_dir"`
	CompanyName       string `toml:"company_name"`
	SupportEmail      string `toml:"support_email"`
	ContactEmail      string `toml:"contact_email"`
	ContactChannel    string `toml:"contact_channel"`
	DocumentationLink string `toml:"documentation_link"`
	RoadmapLink       string `toml:"roadmap_link"`
	Jira              string `toml:"jira"`
}

type endpointsConfig struct {
	VulcanUI    string `toml:"vulcan_ui"`
	ViewReport  string `toml:"view_report"`
	RedirectURL string `toml:"redirect_url"`
}

func ReadConfig(configFile string) (Config, error) {
	configData, err := ioutil.ReadFile(configFile)
	if err != nil {
		return Config{}, err
	}

	var config Config
	if _, err := toml.Decode(string(configData), &config); err != nil {
		return Config{}, err
	}

	return config, nil
}
