package solver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/volcengine/volcengine-go-sdk/service/dns"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/credentials"
	"github.com/volcengine/volcengine-go-sdk/volcengine/request"
	"github.com/volcengine/volcengine-go-sdk/volcengine/response"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
)

type Record struct{ ID, Host, Type, Value string }

type DNS interface {
	List(context.Context, Target) ([]Record, error)
	Create(context.Context, Target, string) (string, error)
	Delete(context.Context, Target, string) error
}

type dnsAPI interface {
	ListRecordsWithContext(volcengine.Context, *dns.ListRecordsInput, ...request.Option) (*dns.ListRecordsOutput, error)
	CreateRecordWithContext(volcengine.Context, *dns.CreateRecordInput, ...request.Option) (*dns.CreateRecordOutput, error)
	DeleteRecordWithContext(volcengine.Context, *dns.DeleteRecordInput, ...request.Option) (*dns.DeleteRecordOutput, error)
}

type VolcDNS struct{ api dnsAPI }

func NewVolcDNS(accessFile, secretFile string) (*VolcDNS, error) {
	read := func(path string) (string, error) {
		if path == "" {
			return "", errors.New("credential file path missing")
		}
		b, err := os.ReadFile(path)
		if err != nil || len(b) == 0 || len(b) > 4096 {
			return "", errors.New("credential file unavailable")
		}
		v := strings.TrimSpace(string(b))
		if v == "" || strings.ContainsAny(v, " \t\r\n") {
			return "", errors.New("invalid credential file")
		}
		return v, nil
	}
	ak, err := read(accessFile)
	if err != nil {
		return nil, err
	}
	sk, err := read(secretFile)
	if err != nil {
		return nil, err
	}
	cfg := volcengine.NewConfig().WithRegion("cn-beijing").WithCredentials(credentials.NewStaticCredentials(ak, sk, "")).WithMaxRetries(0).WithHTTPClient(&http.Client{Timeout: 25 * time.Second})
	sess, err := session.NewSession(cfg)
	if err != nil {
		return nil, errors.New("cannot initialize DNS client")
	}
	return &VolcDNS{api: dns.New(sess)}, nil
}

func responseOK(meta *response.ResponseMetadata, err error) error {
	if err != nil {
		return errors.New("DNS request failed; outcome may be uncertain")
	}
	if meta == nil {
		return errors.New("DNS response metadata missing")
	}
	if meta.Error != nil {
		return fmt.Errorf("DNS API rejected request: %s", meta.Error.Code)
	}
	return nil
}

func (d *VolcDNS) List(ctx context.Context, t Target) ([]Record, error) {
	in := (&dns.ListRecordsInput{}).SetZID(t.ZoneID).SetPageSize(500).SetPageNumber(1)
	out, err := d.api.ListRecordsWithContext(ctx, in)
	if out == nil {
		return nil, errors.New("DNS list returned no response")
	}
	if err = responseOK(out.Metadata, err); err != nil {
		return nil, err
	}
	if out.TotalCount == nil || *out.TotalCount < 0 || *out.TotalCount > 500 || int(*out.TotalCount) != len(out.Records) {
		return nil, errors.New("DNS record inventory incomplete")
	}
	records := make([]Record, 0, len(out.Records))
	for _, r := range out.Records {
		if r == nil || r.RecordID == nil || r.Host == nil || r.Type == nil || r.Value == nil {
			return nil, errors.New("DNS record has missing fields")
		}
		records = append(records, Record{*r.RecordID, *r.Host, *r.Type, *r.Value})
	}
	return records, nil
}

func (d *VolcDNS) Create(ctx context.Context, t Target, value string) (string, error) {
	in := (&dns.CreateRecordInput{}).SetZID(t.ZoneID).SetHost(t.Host).SetType("TXT").SetValue(value).SetTTL(600).SetLine("default")
	out, err := d.api.CreateRecordWithContext(ctx, in)
	if out == nil {
		return "", errors.New("DNS create outcome uncertain")
	}
	if err = responseOK(out.Metadata, err); err != nil {
		return "", err
	}
	if out.RecordID == nil || !recordID.MatchString(*out.RecordID) {
		return "", errors.New("DNS create returned invalid record identity")
	}
	return *out.RecordID, nil
}

func (d *VolcDNS) Delete(ctx context.Context, t Target, id string) error {
	if !recordID.MatchString(id) {
		return errors.New("invalid record ID")
	}
	in := (&dns.DeleteRecordInput{}).SetRecordID(id).SetProjectName(t.Project)
	out, err := d.api.DeleteRecordWithContext(ctx, in)
	if out == nil {
		return errors.New("DNS delete outcome uncertain")
	}
	return responseOK(out.Metadata, err)
}
