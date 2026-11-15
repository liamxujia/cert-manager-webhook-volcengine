package solver

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	acme "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

type memoryJournal struct {
	mu         sync.Mutex
	data       map[string]Entry
	failActive bool
}

func (j *memoryJournal) Update(_ context.Context, key string, fn func(*Entry) (*Entry, bool, error)) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	var current *Entry
	if e, ok := j.data[key]; ok {
		copy := e
		current = &copy
	}
	next, write, err := fn(current)
	if err != nil || !write {
		return err
	}
	if next != nil && next.Phase == "active" && j.failActive {
		return errors.New("journal down")
	}
	if next == nil {
		delete(j.data, key)
	} else {
		j.data[key] = *next
	}
	return nil
}

type memoryDNS struct {
	mu                     sync.Mutex
	records                map[string]Record
	next                   int
	creates, deletes       int
	failCreate, failDelete bool
	project                string
	blockCreate            chan struct{}
	creating               chan struct{}
}

func (d *memoryDNS) List(_ context.Context, t Target) ([]Record, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var result []Record
	for _, r := range d.records {
		result = append(result, r)
	}
	return result, nil
}
func (d *memoryDNS) Create(_ context.Context, t Target, value string) (string, error) {
	d.mu.Lock()
	d.next++
	id := fmt.Sprint(d.next)
	d.creates++
	d.records[id] = Record{ID: id, Host: t.Host, Type: "TXT", Value: value}
	fail := d.failCreate
	d.mu.Unlock()
	if d.creating != nil {
		close(d.creating)
		<-d.blockCreate
	}
	if fail {
		return "", errors.New("connection lost")
	}
	return id, nil
}
func (d *memoryDNS) Delete(_ context.Context, t Target, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.deletes++
	d.project = t.Project
	delete(d.records, id)
	if d.failDelete {
		return errors.New("connection lost")
	}
	return nil
}

func fixture(t *testing.T) (*Solver, *memoryDNS, *memoryJournal, *acme.ChallengeRequest) {
	t.Helper()
	cfg, err := ParseConfig("cert-manager", "dns-journal", "cert-manager", `[{"fqdn":"apps.acme.staging.example.com.","zone":"acme.staging.example.com.","zoneID":123,"project":"example-staging-acme"}]`)
	if err != nil {
		t.Fatal(err)
	}
	j := &memoryJournal{data: map[string]Entry{}}
	d := &memoryDNS{records: map[string]Record{}}
	ch := &acme.ChallengeRequest{Type: "dns-01", ResourceNamespace: "cert-manager", ResolvedFQDN: "apps.acme.staging.example.com.", ResolvedZone: "acme.staging.example.com.", Key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	return &Solver{Config: cfg, DNS: d, Journal: j}, d, j, ch
}

func TestPresentCleanupKeepsForeignRecordsAndSurvivesRestart(t *testing.T) {
	s, d, j, ch := fixture(t)
	d.records["99"] = Record{ID: "99", Host: "apps", Type: "TXT", Value: "foreign"}
	if err := s.Present(ch); err != nil {
		t.Fatal(err)
	}
	if err := s.Present(ch); err != nil {
		t.Fatal(err)
	}
	if d.creates != 1 {
		t.Fatalf("created %d records", d.creates)
	}
	restarted := &Solver{Config: s.Config, DNS: d, Journal: j}
	if err := restarted.CleanUp(ch); err != nil {
		t.Fatal(err)
	}
	if d.deletes != 1 || d.project != "example-staging-acme" || len(d.records) != 1 || d.records["99"].Value != "foreign" {
		t.Fatalf("incorrect cleanup: %+v", d)
	}
	if err := restarted.CleanUp(ch); err != nil {
		t.Fatal(err)
	}
}

func TestUnownedIdenticalRecordCannotBeAdoptedOrDeleted(t *testing.T) {
	s, d, _, ch := fixture(t)
	d.records["99"] = Record{ID: "99", Host: "apps", Type: "TXT", Value: ch.Key}
	if err := s.Present(ch); err == nil {
		t.Fatal("expected conflict")
	}
	if err := s.CleanUp(ch); err == nil {
		t.Fatal("expected unowned-record error")
	}
	if d.creates != 0 || d.deletes != 0 || len(d.records) != 1 {
		t.Fatal("foreign record touched")
	}
}

func TestUncertainCreateRetainsJournalAndDoesNotDelete(t *testing.T) {
	s, d, j, ch := fixture(t)
	d.failCreate = true
	if err := s.Present(ch); err == nil {
		t.Fatal("expected uncertain create")
	}
	if err := s.Present(ch); err == nil {
		t.Fatal("retry must stop")
	}
	if err := s.CleanUp(ch); err == nil {
		t.Fatal("cleanup must stop")
	}
	if d.creates != 1 || d.deletes != 0 || len(j.data) != 1 {
		t.Fatal("uncertain ownership not retained")
	}
}

func TestPersistenceFailureAfterCreateFailsClosed(t *testing.T) {
	s, d, j, ch := fixture(t)
	j.failActive = true
	if err := s.Present(ch); err == nil {
		t.Fatal("expected journal error")
	}
	j.failActive = false
	if err := s.CleanUp(ch); err == nil {
		t.Fatal("must not delete with uncertain ownership")
	}
	if d.creates != 1 || d.deletes != 0 || len(j.data) != 1 {
		t.Fatal("record or journal lost")
	}
}

func TestUncertainDeleteRetainsJournal(t *testing.T) {
	s, d, j, ch := fixture(t)
	if err := s.Present(ch); err != nil {
		t.Fatal(err)
	}
	d.failDelete = true
	if err := s.CleanUp(ch); err == nil {
		t.Fatal("expected uncertain deletion")
	}
	if err := s.CleanUp(ch); err == nil {
		t.Fatal("must not replay uncertain deletion")
	}
	if len(j.data) != 1 || d.deletes != 1 {
		t.Fatal("expected retained journal")
	}
}

func TestChangedRecordIsNeverDeleted(t *testing.T) {
	s, d, _, ch := fixture(t)
	if err := s.Present(ch); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	r := d.records["1"]
	r.Value = "changed"
	d.records["1"] = r
	d.mu.Unlock()
	if err := s.CleanUp(ch); err == nil {
		t.Fatal("expected mismatch")
	}
	if d.deletes != 0 {
		t.Fatal("changed record deleted")
	}
}

func TestMovedRecordIsNeverDeletedOrForgotten(t *testing.T) {
	s, d, j, ch := fixture(t)
	if err := s.Present(ch); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	r := d.records["1"]
	r.Host = "other"
	d.records["1"] = r
	d.mu.Unlock()
	if err := s.CleanUp(ch); err == nil {
		t.Fatal("expected moved record to be detected")
	}
	if d.deletes != 0 || len(j.data) != 1 {
		t.Fatal("moved record was deleted or forgotten")
	}
}

func TestConcurrentSameChallengeDoesNotCreateTwice(t *testing.T) {
	s, d, _, ch := fixture(t)
	d.creating = make(chan struct{})
	d.blockCreate = make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- s.Present(ch) }()
	<-d.creating
	if err := s.Present(ch); err == nil {
		t.Fatal("in-flight operation must be refused")
	}
	close(d.blockCreate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if d.creates != 1 {
		t.Fatalf("created %d records", d.creates)
	}
}

func TestScopeRejectsUnauthorizedTargets(t *testing.T) {
	for _, mutate := range []func(*acme.ChallengeRequest){func(c *acme.ChallengeRequest) { c.ResolvedFQDN = "untrusted.example.com." }, func(c *acme.ChallengeRequest) { c.ResolvedZone = "example.com." }, func(c *acme.ChallengeRequest) { c.ResourceNamespace = "other" }, func(c *acme.ChallengeRequest) { c.Key = "bad" }} {
		s, d, _, ch := fixture(t)
		mutate(ch)
		if err := s.Present(ch); err == nil {
			t.Fatal("expected rejection")
		}
		if d.creates != 0 {
			t.Fatal("out-of-scope write")
		}
	}
}

func TestPerRequestConfigurationCannotChangeScope(t *testing.T) {
	s, d, _, ch := fixture(t)
	ch.Config = &extapi.JSON{Raw: []byte(`{"zoneID":999,"project":"default"}`)}
	if err := s.Present(ch); err == nil || d.creates != 0 {
		t.Fatal("request configuration must not permit DNS writes")
	}
}

func TestConfigurationRejectsInvalidTargets(t *testing.T) {
	tests := []string{`[]`, `[{"fqdn":"apps.example.com.","zone":"evil.com.","zoneID":1,"project":"x"}]`, `[{"fqdn":"apps.example.com.","zone":"example.com.","zoneID":1,"project":"default"}]`, `[{"fqdn":"apps.example.com.","zone":"example.com.","zoneID":1,"project":"x","unrecognized":1}]`, `[{"fqdn":"a.example.com.","zone":"example.com.","zoneID":1,"project":"x"},{"fqdn":"b.example.com.","zone":"example.com.","zoneID":2,"project":"x"}]`}
	for _, value := range tests {
		if _, err := ParseConfig("cert-manager", "journal", "cert-manager", value); err == nil {
			t.Fatalf("accepted invalid config %s", value)
		}
	}
}

func TestDistinctChallengesOnSameHostCanCoexist(t *testing.T) {
	s, d, _, first := fixture(t)
	second := *first
	second.Key = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	errs := make(chan error, 2)
	go func() { errs <- s.Present(first) }()
	go func() { errs <- s.Present(&second) }()
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CleanUp(first); err != nil {
		t.Fatal(err)
	}
	if len(d.records) != 1 {
		t.Fatalf("expected the other challenge to remain: %+v", d.records)
	}
	for _, r := range d.records {
		if r.Value != second.Key {
			t.Fatal("deleted the wrong challenge")
		}
	}
	if err := s.CleanUp(&second); err != nil {
		t.Fatal(err)
	}
	if len(d.records) != 0 {
		t.Fatal("remaining record was not deleted")
	}
}

type blockingListDNS struct {
	DNS
	began   chan struct{}
	release chan struct{}
	once    sync.Once
}

func (d *blockingListDNS) List(ctx context.Context, target Target) ([]Record, error) {
	d.once.Do(func() { close(d.began); <-d.release })
	return d.DNS.List(ctx, target)
}

func TestCleanupOfAbsentChallengeExcludesConcurrentPresent(t *testing.T) {
	s, d, _, ch := fixture(t)
	blocking := &blockingListDNS{DNS: d, began: make(chan struct{}), release: make(chan struct{})}
	s.DNS = blocking
	done := make(chan error, 1)
	go func() { done <- s.CleanUp(ch) }()
	<-blocking.began
	if err := s.Present(ch); err == nil {
		t.Fatal("present must not race the cleanup check")
	}
	close(blocking.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if d.creates != 0 || d.deletes != 0 {
		t.Fatal("unexpected DNS mutation")
	}
	if err := s.Present(ch); err != nil {
		t.Fatal(err)
	}
}
