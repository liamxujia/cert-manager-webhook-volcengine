package solver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var txtValue = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
var recordID = regexp.MustCompile(`^[0-9]{1,32}$`)

type Solver struct {
	Config  Config
	DNS     DNS
	Journal Journal
}

var _ webhook.Solver = (*Solver)(nil)

func (s *Solver) Name() string { return "volcengine" }

func (s *Solver) Initialize(cfg *rest.Config, _ <-chan struct{}) error {
	if s.DNS == nil || len(s.Config.Targets) == 0 {
		return errors.New("solver is not configured")
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return errors.New("cannot initialize Kubernetes client")
	}
	j := &ConfigMapJournal{ConfigMaps: client.CoreV1().ConfigMaps(s.Config.Namespace), Name: s.Config.JournalName}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err = j.Update(ctx, "startup-check", func(*Entry) (*Entry, bool, error) { return nil, false, nil }); err != nil {
		return fmt.Errorf("journal preflight: %w", err)
	}
	s.Journal = j
	return nil
}

func (s *Solver) request(ch *acme.ChallengeRequest) (Target, Entry, string, error) {
	if ch == nil || !s.Config.AllowedNamespaces[ch.ResourceNamespace] {
		return Target{}, Entry{}, "", errors.New("resource namespace not allowed")
	}
	if ch.Type != "dns-01" || !txtValue.MatchString(ch.Key) {
		return Target{}, Entry{}, "", errors.New("invalid DNS-01 challenge")
	}
	if ch.Config != nil && len(bytes.TrimSpace(ch.Config.Raw)) != 0 && !bytes.Equal(bytes.TrimSpace(ch.Config.Raw), []byte("{}")) {
		return Target{}, Entry{}, "", errors.New("per-request configuration is not allowed")
	}
	target, ok := s.Config.Targets[ch.ResolvedFQDN]
	if !ok || target.Zone != ch.ResolvedZone {
		return Target{}, Entry{}, "", errors.New("resolved DNS target not allowed")
	}
	id := sha256.Sum256([]byte(target.FQDN + "\x00" + ch.Key))
	entry := Entry{FQDN: target.FQDN, Zone: target.Zone, ZoneID: target.ZoneID, Project: target.Project, Host: target.Host, Value: ch.Key, Phase: "creating"}
	return target, entry, hex.EncodeToString(id[:]), nil
}

func sameIdentity(a, b Entry) bool {
	return a.FQDN == b.FQDN && a.Zone == b.Zone && a.ZoneID == b.ZoneID && a.Project == b.Project && a.Host == b.Host && a.Value == b.Value
}

func (s *Solver) read(ctx context.Context, key string) (*Entry, error) {
	var current *Entry
	err := s.Journal.Update(ctx, key, func(e *Entry) (*Entry, bool, error) {
		if e != nil {
			copy := *e
			current = &copy
		}
		return nil, false, nil
	})
	return current, err
}

func (s *Solver) transition(ctx context.Context, key string, from, to *Entry) error {
	return s.Journal.Update(ctx, key, func(e *Entry) (*Entry, bool, error) {
		if (e == nil) != (from == nil) || (e != nil && *e != *from) {
			return nil, false, errors.New("journal state changed or operation already in progress")
		}
		return to, true, nil
	})
}

func verifyOwned(records []Record, entry Entry) (bool, error) {
	var match *Record
	for i := range records {
		if records[i].ID == entry.RecordID {
			if match != nil {
				return false, errors.New("duplicate DNS record ID")
			}
			match = &records[i]
		}
	}
	if match == nil {
		return false, nil
	}
	if match.Host != entry.Host || match.Type != "TXT" || match.Value != entry.Value {
		return false, errors.New("owned DNS record changed")
	}
	return true, nil
}

func (s *Solver) Present(ch *acme.ChallengeRequest) error {
	if s.Journal == nil || s.DNS == nil {
		return errors.New("solver not initialized")
	}
	target, initial, key, err := s.request(ch)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	current, err := s.read(ctx, key)
	if err != nil {
		return err
	}
	if current != nil {
		if !sameIdentity(*current, initial) || current.Phase != "active" || !recordID.MatchString(current.RecordID) {
			return errors.New("challenge state requires operator inspection")
		}
		records, err := s.DNS.List(ctx, target)
		if err != nil {
			return err
		}
		found, err := verifyOwned(records, *current)
		if err != nil {
			return err
		}
		if !found {
			return errors.New("owned DNS record not observed")
		}
		return nil
	}
	if err = s.transition(ctx, key, nil, &initial); err != nil {
		return err
	}
	records, err := s.DNS.List(ctx, target)
	if err != nil {
		if releaseErr := s.transition(ctx, key, &initial, nil); releaseErr != nil {
			return errors.New("DNS listing failed and journal claim could not be released")
		}
		return err
	}
	for _, record := range records {
		if record.Host == target.Host && record.Type == "TXT" && record.Value == initial.Value {
			if err = s.transition(ctx, key, &initial, nil); err != nil {
				return errors.New("unowned record exists; journal claim could not be released")
			}
			return errors.New("matching DNS record exists without ownership")
		}
	}
	id, err := s.DNS.Create(ctx, target, initial.Value)
	if err != nil {
		return errors.New("DNS create outcome uncertain; journal retained for inspection")
	}
	if !recordID.MatchString(id) {
		return errors.New("DNS create returned invalid ID; journal retained for inspection")
	}
	active := initial
	active.Phase = "active"
	active.RecordID = id
	if err = s.transition(ctx, key, &initial, &active); err != nil {
		return errors.New("DNS record created but ownership persistence failed; inspect journal")
	}
	records, err = s.DNS.List(ctx, target)
	if err != nil {
		return err
	}
	found, err := verifyOwned(records, active)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("created DNS record not observed")
	}
	return nil
}

func (s *Solver) CleanUp(ch *acme.ChallengeRequest) error {
	if s.Journal == nil || s.DNS == nil {
		return errors.New("solver not initialized")
	}
	target, expected, key, err := s.request(ch)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	current, err := s.read(ctx, key)
	if err != nil {
		return err
	}
	if current == nil {
		checking := expected
		checking.Phase = "checking"
		if err = s.transition(ctx, key, nil, &checking); err != nil {
			return err
		}
		records, err := s.DNS.List(ctx, target)
		if err != nil {
			if releaseErr := s.transition(ctx, key, &checking, nil); releaseErr != nil {
				return errors.New("DNS listing failed and journal claim could not be released")
			}
			return err
		}
		unowned := false
		for _, r := range records {
			if r.Host == target.Host && r.Type == "TXT" && r.Value == expected.Value {
				unowned = true
			}
		}
		if err = s.transition(ctx, key, &checking, nil); err != nil {
			return errors.New("cleanup check could not release journal claim")
		}
		if unowned {
			return errors.New("matching DNS record exists without ownership")
		}
		return nil
	}
	if !sameIdentity(*current, expected) || current.Phase != "active" || !recordID.MatchString(current.RecordID) {
		return errors.New("challenge state requires operator inspection")
	}
	deleting := *current
	deleting.Phase = "deleting"
	if err = s.transition(ctx, key, current, &deleting); err != nil {
		return err
	}
	records, err := s.DNS.List(ctx, target)
	if err != nil {
		return err
	}
	found, err := verifyOwned(records, deleting)
	if err != nil {
		return err
	}
	if found {
		if err = s.DNS.Delete(ctx, target, deleting.RecordID); err != nil {
			return errors.New("DNS delete outcome uncertain; journal retained for inspection")
		}
		records, err = s.DNS.List(ctx, target)
		if err != nil {
			return err
		}
		found, err = verifyOwned(records, deleting)
		if err != nil {
			return err
		}
		if found {
			return errors.New("deleted DNS record remains; journal retained for inspection")
		}
	}
	if err = s.transition(ctx, key, &deleting, nil); err != nil {
		return errors.New("DNS cleanup complete but journal update failed; inspect journal")
	}
	return nil
}
