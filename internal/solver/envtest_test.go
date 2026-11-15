//go:build integration

package solver

import (
	"context"
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestRealAPIServerJournalConcurrentChallenges(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Fatal("KUBEBUILDER_ASSETS must identify the envtest binaries")
	}
	environment := &envtest.Environment{}
	config, err := environment.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := environment.Stop(); err != nil {
			t.Error(err)
		}
	})
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err = client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "cert-manager"}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = client.CoreV1().ConfigMaps("cert-manager").Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "dns-journal", Namespace: "cert-manager"}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	original, dns, _, first := fixture(t)
	makeSolver := func() *Solver {
		t.Helper()
		s := &Solver{Config: original.Config, DNS: dns}
		if err := s.Initialize(config, make(chan struct{})); err != nil {
			t.Fatal(err)
		}
		return s
	}
	firstSolver, secondSolver := makeSolver(), makeSolver()
	second := *first
	second.Key = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	errs := make(chan error, 2)
	go func() { errs <- firstSolver.Present(first) }()
	go func() { errs <- secondSolver.Present(&second) }()
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	cm, err := client.CoreV1().ConfigMaps("cert-manager").Get(ctx, "dns-journal", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cm.Data) != 2 {
		t.Fatalf("journal lost a concurrent entry: %d", len(cm.Data))
	}
	if err := makeSolver().CleanUp(first); err != nil {
		t.Fatal(err)
	}
	if err := makeSolver().CleanUp(&second); err != nil {
		t.Fatal(err)
	}
	cm, err = client.CoreV1().ConfigMaps("cert-manager").Get(ctx, "dns-journal", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cm.Data) != 0 || len(dns.records) != 0 {
		t.Fatal("expected journal and provider cleanup")
	}
}
