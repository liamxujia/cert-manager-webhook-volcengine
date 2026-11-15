package charts

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	kyaml "k8s.io/apimachinery/pkg/util/yaml"
)

func helm(t *testing.T) string {
	t.Helper()
	binary := os.Getenv("HELM")
	if binary == "" {
		var err error
		binary, err = exec.LookPath("helm")
		if err != nil {
			t.Skip("install Helm or set HELM to validate the chart")
		}
	}
	return binary
}

func TestChartRestrictsJournalAndRequiresPinnedInputs(t *testing.T) {
	h := helm(t)
	chart := "./volcengine-dns01"
	bad := exec.Command(h, "template", "test", chart, "--namespace", "cert-manager")
	if err := bad.Run(); err == nil {
		t.Fatal("chart accepted missing image and targets")
	}
	values := filepath.Join(t.TempDir(), "values.json")
	cfg := map[string]any{"groupName": "dns.example.com", "image": "example.invalid/webhook@sha256:" + strings.Repeat("a", 64), "targets": []map[string]any{{"fqdn": "apps.acme.example.com.", "zone": "acme.example.com.", "zoneID": 123, "project": "test-acme"}}}
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(values, b, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(h, "template", "test", chart, "--namespace", "cert-manager", "-f", values)
	rendered, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("render failed: %s", rendered)
	}
	decoder := kyaml.NewYAMLOrJSONDecoder(bytes.NewReader(rendered), 4096)
	var role, solverRole, deploy, api, service *unstructured.Unstructured
	for {
		var item map[string]any
		err = decoder.Decode(&item)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(item) == 0 {
			continue
		}
		obj := &unstructured.Unstructured{Object: item}
		if obj.GetKind() == "Role" || obj.GetKind() == "ClusterRole" {
			rules, _, _ := unstructured.NestedSlice(obj.Object, "rules")
			for _, rule := range rules {
				resources, _, _ := unstructured.NestedStringSlice(rule.(map[string]any), "resources")
				for _, resource := range resources {
					if resource == "secrets" || resource == "*" {
						t.Fatalf("unexpected broad resource %q in %s", resource, obj.GetName())
					}
				}
			}
		}
		switch obj.GetKind() + "/" + obj.GetName() {
		case "Role/volcengine-dns01-journal":
			role = obj
		case "ClusterRole/volcengine-dns01-solver":
			solverRole = obj
		case "Deployment/volcengine-dns01":
			deploy = obj
		case "APIService/v1alpha1.dns.example.com":
			api = obj
		case "Service/volcengine-dns01":
			service = obj
		}
	}
	if role == nil || solverRole == nil || deploy == nil || api == nil || service == nil {
		t.Fatal("chart omitted required resources")
	}
	rules, found, err := unstructured.NestedSlice(role.Object, "rules")
	if err != nil || !found || len(rules) != 1 {
		t.Fatal("journal role invalid")
	}
	r := rules[0].(map[string]any)
	resources, _, _ := unstructured.NestedStringSlice(r, "resources")
	names, _, _ := unstructured.NestedStringSlice(r, "resourceNames")
	verbs, _, _ := unstructured.NestedStringSlice(r, "verbs")
	if strings.Join(resources, ",") != "configmaps" || strings.Join(names, ",") != "volcengine-dns01-journal" || strings.Join(verbs, ",") != "get,update" {
		t.Fatal("journal role is not resource-scoped")
	}
	containers, found, err := unstructured.NestedSlice(deploy.Object, "spec", "template", "spec", "containers")
	if err != nil || !found || len(containers) != 1 {
		t.Fatal("unexpected deployment containers")
	}
	image, _, _ := unstructured.NestedString(containers[0].(map[string]any), "image")
	if image != cfg["image"] {
		t.Fatal("deployment did not use the pinned image")
	}
	env, _, _ := unstructured.NestedSlice(containers[0].(map[string]any), "env")
	groupFound := false
	for _, e := range env {
		item := e.(map[string]any)
		if item["name"] == "GROUP_NAME" && item["value"] == cfg["groupName"] {
			groupFound = true
		}
	}
	if !groupFound {
		t.Fatal("deployment did not use the configured group")
	}
	apiGroup, _, _ := unstructured.NestedString(api.Object, "spec", "group")
	solverRules, _, _ := unstructured.NestedSlice(solverRole.Object, "rules")
	groups, _, _ := unstructured.NestedStringSlice(solverRules[0].(map[string]any), "apiGroups")
	if apiGroup != cfg["groupName"] || len(groups) != 1 || groups[0] != apiGroup {
		t.Fatal("APIService and solver role use inconsistent groups")
	}
	ca := api.GetAnnotations()["cert-manager.io/inject-ca-from"]
	if ca != "cert-manager/volcengine-dns01-serving" {
		t.Fatalf("incorrect APIService CA source %q", ca)
	}
}

func TestChartRejectsInvalidGroup(t *testing.T) {
	h := helm(t)
	for _, group := range []string{"", "localhost", "UPPER.example.com", "a..example.com"} {
		t.Run(group, func(t *testing.T) {
			values := filepath.Join(t.TempDir(), "values.json")
			cfg := map[string]any{"groupName": group, "image": "example.invalid/webhook@sha256:" + strings.Repeat("a", 64), "targets": []map[string]any{{"fqdn": "apps.acme.example.com.", "zone": "acme.example.com.", "zoneID": 123, "project": "test-acme"}}}
			data, _ := json.Marshal(cfg)
			if err := os.WriteFile(values, data, 0600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command(h, "template", "test", "./volcengine-dns01", "-f", values).CombinedOutput(); err == nil {
				t.Fatalf("chart accepted invalid group %q: %s", group, out)
			}
		})
	}
}
