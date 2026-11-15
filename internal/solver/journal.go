package solver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coretyped "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/util/retry"
)

type Entry struct {
	FQDN     string `json:"fqdn"`
	Zone     string `json:"zone"`
	ZoneID   int64  `json:"zoneID"`
	Project  string `json:"project"`
	Host     string `json:"host"`
	Value    string `json:"value"`
	Phase    string `json:"phase"`
	RecordID string `json:"recordID,omitempty"`
}

type Journal interface {
	Update(context.Context, string, func(*Entry) (*Entry, bool, error)) error
}

type ConfigMapJournal struct {
	ConfigMaps coretyped.ConfigMapInterface
	Name       string
}

func (j *ConfigMapJournal) Update(ctx context.Context, key string, fn func(*Entry) (*Entry, bool, error)) error {
	if j.ConfigMaps == nil || j.Name == "" {
		return errors.New("journal is not configured")
	}
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		cm, err := j.ConfigMaps.Get(ctx, j.Name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("read journal: %w", err)
		}
		if cm.Immutable != nil && *cm.Immutable {
			return errors.New("journal is immutable")
		}
		var current *Entry
		if raw, ok := cm.Data[key]; ok {
			current = new(Entry)
			if err := json.Unmarshal([]byte(raw), current); err != nil {
				return errors.New("invalid journal entry")
			}
		}
		next, write, err := fn(current)
		if err != nil || !write {
			return err
		}
		copy := cm.DeepCopy()
		if copy.Data == nil {
			copy.Data = map[string]string{}
		}
		if next == nil {
			delete(copy.Data, key)
		} else {
			value, err := json.Marshal(next)
			if err != nil {
				return err
			}
			copy.Data[key] = string(value)
		}
		_, err = j.ConfigMaps.Update(ctx, copy, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("write journal: %w", err)
		}
		return nil
	})
}

var _ Journal = (*ConfigMapJournal)(nil)
