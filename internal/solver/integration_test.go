package solver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/volcengine/volcengine-go-sdk/service/dns"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/credentials"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestSolverWithSDKAndKubernetesJournal(t *testing.T) {
	base, _, _, ch := fixture(t)
	var mu sync.Mutex
	records := map[string]Record{"99": {ID: "99", Host: "apps", Type: "TXT", Value: "foreign"}}
	next := 1
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") == "" {
			t.Error("missing SDK request signature")
		}
		action := r.URL.Query().Get("Action")
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode %s: %v", action, err)
			w.WriteHeader(400)
			return
		}
		result := map[string]any{}
		switch action {
		case "ListRecords":
			if body["ZID"] != float64(123) || body["Host"] != nil || body["Type"] != nil {
				t.Errorf("list scope: %v", body)
			}
			rows := make([]map[string]string, 0, len(records))
			for _, v := range records {
				rows = append(rows, map[string]string{"RecordID": v.ID, "Host": v.Host, "Type": v.Type, "Value": v.Value})
			}
			result["TotalCount"] = len(rows)
			result["Records"] = rows
		case "CreateRecord":
			if body["ZID"] != float64(123) || body["Host"] != "apps" || body["Type"] != "TXT" {
				t.Errorf("create scope: %v", body)
			}
			id := strconv.Itoa(next)
			next++
			records[id] = Record{ID: id, Host: "apps", Type: "TXT", Value: body["Value"].(string)}
			result["RecordID"] = id
		case "DeleteRecord":
			if body["ProjectName"] != "example-staging-acme" {
				t.Errorf("wrong project: %v", body)
			}
			id, _ := body["RecordID"].(string)
			if id == "99" {
				t.Error("foreign record deletion")
			}
			delete(records, id)
		default:
			t.Errorf("unexpected action %q", action)
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ResponseMetadata": map[string]any{"RequestId": "test", "Action": action, "Version": "2018-08-01", "Service": "dns", "Region": "cn-beijing"}, "Result": result})
	}))
	defer server.Close()
	config := volcengine.NewConfig().WithRegion("cn-beijing").WithEndpoint(server.URL).WithDisableSSL(true).WithCredentials(credentials.NewStaticCredentials("test-access", "test-secret", "")).WithMaxRetries(0).WithHTTPClient(server.Client())
	session, err := session.NewSession(config)
	if err != nil {
		t.Fatal(err)
	}
	kube := fake.NewSimpleClientset(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "dns-journal", Namespace: "cert-manager"}})
	journal := &ConfigMapJournal{ConfigMaps: kube.CoreV1().ConfigMaps("cert-manager"), Name: "dns-journal"}
	provider := &VolcDNS{api: dns.New(session)}
	first := &Solver{Config: base.Config, DNS: provider, Journal: journal}
	if err := first.Present(ch); err != nil {
		t.Fatal(err)
	}
	restarted := &Solver{Config: base.Config, DNS: provider, Journal: journal}
	if err := restarted.CleanUp(ch); err != nil {
		t.Fatal(err)
	}
	cm, err := kube.CoreV1().ConfigMaps("cert-manager").Get(context.Background(), "dns-journal", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(cm.Data) != 0 || len(records) != 1 || records["99"].Value != "foreign" {
		t.Fatal(fmt.Sprintf("incorrect final state: journal entries=%d records=%d", len(cm.Data), len(records)))
	}
}
