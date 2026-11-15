package solver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

type Target struct {
	FQDN    string `json:"fqdn"`
	Zone    string `json:"zone"`
	ZoneID  int64  `json:"zoneID"`
	Project string `json:"project"`
	Host    string `json:"-"`
}

type Config struct {
	Namespace         string
	JournalName       string
	AllowedNamespaces map[string]bool
	Targets           map[string]Target
}

var projectName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
var dnsName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.$`)
var namespaceName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func LoadConfig() (Config, error) {
	return ParseConfig(os.Getenv("POD_NAMESPACE"), os.Getenv("JOURNAL_NAME"), os.Getenv("ALLOWED_NAMESPACES"), os.Getenv("DNS_TARGETS_JSON"))
}

func ParseConfig(namespace, journal, namespaces, targetsJSON string) (Config, error) {
	if !namespaceName.MatchString(namespace) || !dnsName.MatchString(journal+".") || len(journal) > 253 {
		return Config{}, errors.New("invalid journal namespace or name")
	}
	allowed := make(map[string]bool)
	for _, n := range strings.Split(namespaces, ",") {
		if !namespaceName.MatchString(n) {
			return Config{}, errors.New("invalid allowed namespace")
		}
		allowed[n] = true
	}
	var targets []Target
	decoder := json.NewDecoder(strings.NewReader(targetsJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&targets); err != nil {
		return Config{}, fmt.Errorf("invalid targets: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return Config{}, errors.New("invalid trailing target data")
	}
	if len(targets) == 0 || len(targets) > 100 {
		return Config{}, errors.New("expected 1 to 100 targets")
	}
	configured := make(map[string]Target, len(targets))
	zoneIDs := make(map[int64]Target)
	zones := make(map[string]Target)
	for _, t := range targets {
		if !dnsName.MatchString(t.FQDN) || !dnsName.MatchString(t.Zone) || len(t.FQDN) > 254 || t.ZoneID <= 0 || !projectName.MatchString(t.Project) || t.Project == "default" {
			return Config{}, errors.New("invalid target")
		}
		suffix := "." + t.Zone
		if !strings.HasSuffix(t.FQDN, suffix) {
			return Config{}, errors.New("target must be below its zone")
		}
		t.Host = strings.TrimSuffix(t.FQDN, suffix)
		if t.Host == "" || len(t.Host) > 253 {
			return Config{}, errors.New("invalid target host")
		}
		if _, ok := configured[t.FQDN]; ok {
			return Config{}, errors.New("duplicate target")
		}
		if previous, ok := zoneIDs[t.ZoneID]; ok && (previous.Zone != t.Zone || previous.Project != t.Project) {
			return Config{}, errors.New("zone ID maps to conflicting zone or project")
		}
		if previous, ok := zones[t.Zone]; ok && (previous.ZoneID != t.ZoneID || previous.Project != t.Project) {
			return Config{}, errors.New("zone maps to conflicting ID or project")
		}
		zoneIDs[t.ZoneID] = t
		zones[t.Zone] = t
		configured[t.FQDN] = t
	}
	return Config{Namespace: namespace, JournalName: journal, AllowedNamespaces: allowed, Targets: configured}, nil
}
