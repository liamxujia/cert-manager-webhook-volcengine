package solver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/volcengine/volcengine-go-sdk/service/dns"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/credentials"
	"github.com/volcengine/volcengine-go-sdk/volcengine/request"
	"github.com/volcengine/volcengine-go-sdk/volcengine/response"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
)

type fakeAPI struct {
	list        *dns.ListRecordsOutput
	listInput   *dns.ListRecordsInput
	createInput *dns.CreateRecordInput
	deleteInput *dns.DeleteRecordInput
	err         error
}

func (f *fakeAPI) ListRecordsWithContext(_ volcengine.Context, in *dns.ListRecordsInput, _ ...request.Option) (*dns.ListRecordsOutput, error) {
	f.listInput = in
	return f.list, f.err
}
func (f *fakeAPI) CreateRecordWithContext(_ volcengine.Context, in *dns.CreateRecordInput, _ ...request.Option) (*dns.CreateRecordOutput, error) {
	f.createInput = in
	return &dns.CreateRecordOutput{Metadata: &response.ResponseMetadata{}, RecordID: volcengine.String("123")}, f.err
}
func (f *fakeAPI) DeleteRecordWithContext(_ volcengine.Context, in *dns.DeleteRecordInput, _ ...request.Option) (*dns.DeleteRecordOutput, error) {
	f.deleteInput = in
	return &dns.DeleteRecordOutput{Metadata: &response.ResponseMetadata{}}, f.err
}

func TestVolcDNSRequestsUseExactTargetAndProject(t *testing.T) {
	target := Target{FQDN: "apps.acme.example.com.", Zone: "acme.example.com.", ZoneID: 123, Host: "apps", Project: "example-staging-acme"}
	api := &fakeAPI{list: &dns.ListRecordsOutput{Metadata: &response.ResponseMetadata{}, TotalCount: volcengine.Int32(1), Records: []*dns.RecordForListRecordsOutput{{RecordID: volcengine.String("123"), Host: volcengine.String("apps"), Type: volcengine.String("TXT"), Value: volcengine.String("value")}}}}
	client := &VolcDNS{api: api}
	ctx := context.Background()
	rows, err := client.List(ctx, target)
	if err != nil || len(rows) != 1 {
		t.Fatalf("list: %v", err)
	}
	if *api.listInput.ZID != 123 || api.listInput.Host != nil || api.listInput.Type != nil {
		t.Fatal("list scope incorrect")
	}
	id, err := client.Create(ctx, target, "value")
	if err != nil || id != "123" || *api.createInput.ZID != 123 || *api.createInput.Host != "apps" || *api.createInput.Type != "TXT" {
		t.Fatalf("create: %v", err)
	}
	if err = client.Delete(ctx, target, id); err != nil {
		t.Fatal(err)
	}
	if *api.deleteInput.ProjectName != "example-staging-acme" || *api.deleteInput.RecordID != "123" {
		t.Fatal("delete is not project and record scoped")
	}
}

func TestVolcDNSRejectsIncompleteAndFailedResponses(t *testing.T) {
	target := Target{ZoneID: 123, Host: "apps", Project: "example-staging-acme"}
	api := &fakeAPI{list: &dns.ListRecordsOutput{Metadata: &response.ResponseMetadata{}, TotalCount: volcengine.Int32(2)}}
	client := &VolcDNS{api: api}
	if _, err := client.List(context.Background(), target); err == nil {
		t.Fatal("accepted incomplete list")
	}
	api.err = errors.New("network failed")
	if _, err := client.Create(context.Background(), target, "value"); err == nil {
		t.Fatal("accepted failed create")
	}
	if err := client.Delete(context.Background(), target, "123"); err == nil {
		t.Fatal("accepted failed delete")
	}
	if err := client.Delete(context.Background(), target, "not-an-id"); err == nil {
		t.Fatal("accepted bad record ID")
	}
}

func TestSDKSerializesProjectName(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ResponseMetadata":{"RequestId":"test","Action":"DeleteRecord","Version":"2018-08-01","Service":"dns","Region":"cn-beijing"},"Result":{}}`)
	}))
	defer server.Close()
	cfg := volcengine.NewConfig().WithRegion("cn-beijing").WithEndpoint(server.URL).WithDisableSSL(true).WithCredentials(credentials.NewStaticCredentials("test-access", "test-secret", "")).WithMaxRetries(0).WithHTTPClient(server.Client())
	sess, err := session.NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client := &VolcDNS{api: dns.New(sess)}
	if err = client.Delete(context.Background(), Target{Project: "example-staging-acme"}, "123"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 || payload["RecordID"] != "123" || payload["ProjectName"] != "example-staging-acme" {
		t.Fatalf("unexpected provider request: calls=%d payload=%v", calls, payload)
	}
}

func TestSDKDoesNotRetryAmbiguousCreate(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	cfg := volcengine.NewConfig().WithRegion("cn-beijing").WithEndpoint(server.URL).WithDisableSSL(true).WithCredentials(credentials.NewStaticCredentials("test-access", "test-secret", "")).WithMaxRetries(0).WithHTTPClient(server.Client())
	sess, err := session.NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client := &VolcDNS{api: dns.New(sess)}
	if _, err = client.Create(context.Background(), Target{ZoneID: 123, Host: "apps"}, "value"); err == nil {
		t.Fatal("expected provider failure")
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("unsafe retry count: %d", calls)
	}
}
