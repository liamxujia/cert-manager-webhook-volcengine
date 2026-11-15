package solver

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

func TestConfigMapJournalRetriesConflictsAndPreservesOtherEntries(t *testing.T) {
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "journal", Namespace: "cert-manager"}, Data: map[string]string{"unrelated": "preserve"}}
	client := fake.NewSimpleClientset(cm)
	conflicts := 0
	client.PrependReactor("update", "configmaps", func(a clienttesting.Action) (bool, runtime.Object, error) {
		if conflicts == 0 {
			conflicts++
			concurrent := cm.DeepCopy()
			concurrent.Data["concurrent"] = "retained"
			if err := client.Tracker().Update(schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}, concurrent, "cert-manager"); err != nil {
				t.Fatal(err)
			}
			return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, "journal", nil)
		}
		return false, nil, nil
	})
	j := &ConfigMapJournal{ConfigMaps: client.CoreV1().ConfigMaps("cert-manager"), Name: "journal"}
	entry := &Entry{FQDN: "target.", Phase: "creating"}
	if err := j.Update(context.Background(), "key", func(e *Entry) (*Entry, bool, error) {
		if e != nil {
			t.Fatal("unexpected entry")
		}
		return entry, true, nil
	}); err != nil {
		t.Fatal(err)
	}
	got, err := client.CoreV1().ConfigMaps("cert-manager").Get(context.Background(), "journal", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if conflicts != 1 || got.Data["unrelated"] != "preserve" || got.Data["concurrent"] != "retained" || got.Data["key"] == "" {
		t.Fatal("journal conflict or unrelated data mishandled")
	}
}

func TestConfigMapJournalRejectsCorruptEntryAndMissingMap(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "journal", Namespace: "cert-manager"}, Data: map[string]string{"key": "{"}})
	j := &ConfigMapJournal{ConfigMaps: client.CoreV1().ConfigMaps("cert-manager"), Name: "journal"}
	if err := j.Update(context.Background(), "key", func(*Entry) (*Entry, bool, error) { t.Fatal("called with corrupt entry"); return nil, false, nil }); err == nil {
		t.Fatal("accepted corrupt entry")
	}
	j.Name = "missing"
	if err := j.Update(context.Background(), "key", func(*Entry) (*Entry, bool, error) { return nil, false, nil }); err == nil {
		t.Fatal("accepted missing map")
	}
}
