package db

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// Стандартные имена файлов в каталоге БД.
const (
	FileTypes       = "types.json"
	FileEmitents    = "emitents.json"
	FileAuthorities = "authorities.json"
	FileDocuments   = "documents.json"
	FileNodes       = "nodes.json"
	FileLogs        = "logs.json"
	FileAttackLogs  = "attack_logs.json"
)

// Database — простая файловая БД (один JSON на сущность).
type Database struct {
	Dir string
	mu  sync.Mutex
}

func Open(dir string) (*Database, error) {
	if dir == "" {
		dir = "db"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	d := &Database{Dir: dir}
	if err := d.ensureDefaults(); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *Database) Path(name string) string {
	return filepath.Join(d.Dir, name)
}

func (d *Database) ReadJSON(name string, out interface{}) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	b, err := os.ReadFile(d.Path(name))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func (d *Database) WriteJSON(name string, v interface{}) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := d.Path(name) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, d.Path(name))
}

func writeIfAbsent(path string, data []byte) error {
	_, err := os.Stat(path)
	if err == nil {
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func (d *Database) ensureDefaults() error {
	dir := d.Dir
	defaults := map[string][]byte{
		FileTypes: []byte(`{
  "types": [
    {"id": "diploma", "label_ru": "Диплом"},
    {"id": "tax_record", "label_ru": "Налоговая справка"},
    {"id": "certificate", "label_ru": "Сертификат квалификации"}
  ]
}`),
		FileEmitents: []byte(`{
  "emitters": [
    {"code": "BY", "name_ru": "Республика Беларусь"},
    {"code": "RU", "name_ru": "Российская Федерация"},
    {"code": "KZ", "name_ru": "Республика Казахстан"},
    {"code": "AM", "name_ru": "Республика Армения"},
    {"code": "AZ", "name_ru": "Республика Азербайджан"}
  ]
}`),
		FileAuthorities: []byte(`{
  "authorities": [
    {"id": "by-mo", "country_code": "BY", "name_ru": "Министерство образования РБ"},
    {"id": "by-ms", "country_code": "BY", "name_ru": "Министерство здравоохранения РБ"},
    {"id": "ru-minsvyaz", "country_code": "RU", "name_ru": "Минпросвещения России"},
    {"id": "ru-fns", "country_code": "RU", "name_ru": "ФНС России"},
    {"id": "kz-mon", "country_code": "KZ", "name_ru": "Министерство образования РК"},
    {"id": "am-gov", "country_code": "AM", "name_ru": "Государственный орган Армении"},
    {"id": "az-gov", "country_code": "AZ", "name_ru": "Государственный орган Азербайджана"}
  ]
}`),
		FileDocuments:  []byte(`{"documents": []}`),
		FileNodes:      []byte(`{"nodes": [], "gossip_events": [], "gossip_votes": []}`),
		FileLogs:       []byte(`{"entries": []}`),
		FileAttackLogs: []byte(`{"lines": []}`),
	}
	for name, body := range defaults {
		if err := writeIfAbsent(filepath.Join(dir, name), body); err != nil {
			return err
		}
	}
	return nil
}
