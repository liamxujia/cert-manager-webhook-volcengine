package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	volcengine "github.com/liamxujia/cert-manager-webhook-volcengine"
	"k8s.io/apimachinery/pkg/util/validation"
)

func validateGroup(group string) error {
	if !strings.Contains(group, ".") || len(validation.IsDNS1123Subdomain(group)) != 0 {
		return fmt.Errorf("GROUP_NAME must be a lowercase DNS subdomain with at least two labels")
	}
	return nil
}

func main() {
	group := os.Getenv("GROUP_NAME")
	if err := validateGroup(group); err != nil {
		log.Fatal(err)
	}
	provider, err := volcengine.NewFromEnvironment()
	if err != nil {
		log.Fatal(err)
	}
	cmd.RunWebhookServer(group, provider)
}
