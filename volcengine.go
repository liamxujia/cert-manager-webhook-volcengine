// Package volcengine provides a restricted Volcengine DNS-01 solver for cert-manager.
// The solver uses an explicit target allowlist and persists DNS record ownership
// in a Kubernetes ConfigMap. See the package README for operational constraints.
package volcengine

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/liamxujia/cert-manager-webhook-volcengine/internal/solver"
	"k8s.io/client-go/rest"
)

// Target identifies an allowed DNS-01 destination within a dedicated DNS project.
// FQDN and Zone must be lowercase fully qualified names ending in a dot.
// ZoneID must identify Zone, and FQDN must be strictly below Zone.
type Target struct {
	FQDN    string `json:"fqdn"`
	Zone    string `json:"zone"`
	ZoneID  int64  `json:"zoneID"`
	Project string `json:"project"`
}

// Config defines the journal location and the complete request allowlist.
type Config struct {
	JournalNamespace  string
	JournalName       string
	AllowedNamespaces []string
	Targets           []Target
}

// CredentialFiles identifies files containing a dedicated Volcengine access key
// and secret key. Both files are read once during construction.
type CredentialFiles struct {
	AccessKeyPath string
	SecretKeyPath string
}

// Solver implements cert-manager's webhook.Solver. Construct it with New or
// NewFromEnvironment, then call Initialize before Present or CleanUp.
type Solver struct {
	inner *solver.Solver
}

var _ webhook.Solver = (*Solver)(nil)

// New validates and copies the allowlist, loads credentials, and constructs a
// solver. It does not contact Kubernetes or Volcengine during construction.
func New(config Config, files CredentialFiles) (*Solver, error) {
	for _, namespace := range config.AllowedNamespaces {
		if strings.Contains(namespace, ",") {
			return nil, errors.New("invalid allowed namespace")
		}
	}
	targets, err := json.Marshal(config.Targets)
	if err != nil {
		return nil, err
	}
	parsed, err := solver.ParseConfig(config.JournalNamespace, config.JournalName, strings.Join(config.AllowedNamespaces, ","), string(targets))
	if err != nil {
		return nil, err
	}
	return newSolver(parsed, files)
}

// NewFromEnvironment constructs the solver using the environment variables
// documented in README.md. It applies the same validation as New.
func NewFromEnvironment() (*Solver, error) {
	config, err := solver.LoadConfig()
	if err != nil {
		return nil, err
	}
	return newSolver(config, credentialFilesFromEnvironment())
}

func newSolver(config solver.Config, files CredentialFiles) (*Solver, error) {
	provider, err := solver.NewVolcDNS(files.AccessKeyPath, files.SecretKeyPath)
	if err != nil {
		return nil, err
	}
	return &Solver{inner: &solver.Solver{Config: config, DNS: provider}}, nil
}

// Name returns the cert-manager solver name, "volcengine".
func (s *Solver) Name() string { return "volcengine" }

// Initialize attaches the solver to its pre-existing Kubernetes journal.
func (s *Solver) Initialize(config *rest.Config, stop <-chan struct{}) error {
	if s == nil || s.inner == nil {
		return errors.New("solver must be constructed with New or NewFromEnvironment")
	}
	return s.inner.Initialize(config, stop)
}

// Present creates or verifies the journal-owned DNS-01 record.
func (s *Solver) Present(request *acme.ChallengeRequest) error {
	if s == nil || s.inner == nil {
		return errors.New("solver must be constructed with New or NewFromEnvironment")
	}
	return s.inner.Present(request)
}

// CleanUp removes only the verified record owned by this solver's journal.
func (s *Solver) CleanUp(request *acme.ChallengeRequest) error {
	if s == nil || s.inner == nil {
		return errors.New("solver must be constructed with New or NewFromEnvironment")
	}
	return s.inner.CleanUp(request)
}
