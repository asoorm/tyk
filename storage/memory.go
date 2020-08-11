package storage

import (
	"context"
	"time"

	"github.com/buraksezer/olric"
	"github.com/buraksezer/olric/config"
)

func NewMemory() (*Memory, error) {
	// config.New returns a new config.Config with sane defaults. Available values for env:
	// local, lan, wan
	c := config.New("local")

	// Callback function. It's called when this node is ready to accept connections.
	ctx, cancel := context.WithCancel(context.Background())
	c.Started = func() {
		defer cancel()
		log.Println("[INFO] Olric is ready to accept connections")
	}

	db, err := olric.New(c)
	if err != nil {
		log.Fatalf("Failed to create Olric instance: %v", err)
	}

	go func() {
		// Call Start at background. It's a blocker call.
		err = db.Start()
		if err != nil {
			log.Fatalf("olric.Start returned an error: %v", err)
		}
	}()

	<-ctx.Done()

	dm, err := db.NewDMap("olric-memory")
	if err != nil {
		log.Fatalf("olric.NewDMap returned an error: %v", err)
	}

	return &Memory{
		db: dm,
	}, nil
}

type Memory struct {
	db        *olric.DMap
	KeyPrefix string
	HashKeys  bool
	IsCache   bool
}

func (m *Memory) fixKey(keyName string) string {
	return m.KeyPrefix + m.hashKey(keyName)
}

func (m *Memory) hashKey(in string) string {
	if !m.HashKeys {
		// Not hashing? Return the raw key
		return in
	}
	return HashStr(in)
}

func (m Memory) GetKey(key string) (string, error) {
	val, err := m.db.Get(m.fixKey(key))
	if err != nil {
		log.Debug("Error trying to get value:", err)
		return "", ErrKeyNotFound
	}
	return val.(string), nil
}

func (m *Memory) GetMultiKey(keys []string) ([]string, error) {
	var values []string
	for i := range keys {
		val, _ := m.GetKey(keys[i])
		values = append(values, val)
	}
	return values, nil
}

func (m *Memory) GetRawKey(key string) (string, error) {
	val, err := m.db.Get(key)
	if err != nil {
		log.Debug("Error trying to get value:", err)
		return "", ErrKeyNotFound
	}
	return val.(string), nil
}

func (m *Memory) SetKey(key string, session string, timeout int64) error {
	if err := m.db.PutEx(m.fixKey(key), session, time.Duration(timeout)*time.Second); err != nil {
		log.Error("Error trying to set value: ", err)
		return err
	}
	return nil
}

func (m *Memory) SetRawKey(key string, session string, timeout int64) error {
	if err := m.db.PutEx(key, session, time.Duration(timeout)*time.Second); err != nil {
		log.Error("Error trying to set value: ", err)
		return err
	}
	return nil
}

func (Memory) SetExp(s string, i int64) error {
	panic("implement me")
}

func (Memory) GetExp(s string) (int64, error) {
	panic("implement me")
}

func (Memory) GetKeys(s string) []string {
	panic("implement me")
}

func (Memory) DeleteKey(s string) bool {
	panic("implement me")
}

func (Memory) DeleteAllKeys() bool {
	panic("implement me")
}

func (Memory) DeleteRawKey(s string) bool {
	panic("implement me")
}

func (Memory) Connect() bool {
	panic("implement me")
}

func (Memory) GetKeysAndValues() map[string]string {
	panic("implement me")
}

func (Memory) GetKeysAndValuesWithFilter(s string) map[string]string {
	panic("implement me")
}

func (Memory) DeleteKeys(strings []string) bool {
	panic("implement me")
}

func (Memory) Decrement(s string) {
	panic("implement me")
}

func (Memory) IncrememntWithExpire(s string, i int64) int64 {
	panic("implement me")
}

func (Memory) SetRollingWindow(key string, per int64, val string, pipeline bool) (int, []interface{}) {
	panic("implement me")
}

func (Memory) GetRollingWindow(key string, per int64, pipeline bool) (int, []interface{}) {
	panic("implement me")
}

func (Memory) GetSet(s string) (map[string]string, error) {
	panic("implement me")
}

func (Memory) AddToSet(s string, s2 string) {
	panic("implement me")
}

func (Memory) GetAndDeleteSet(s string) []interface{} {
	panic("implement me")
}

func (Memory) RemoveFromSet(s string, s2 string) {
	panic("implement me")
}

func (Memory) DeleteScanMatch(s string) bool {
	panic("implement me")
}

func (Memory) GetKeyPrefix() string {
	panic("implement me")
}

func (Memory) AddToSortedSet(s string, s2 string, f float64) {
	panic("implement me")
}

func (Memory) GetSortedSetRange(s string, s2 string, s3 string) ([]string, []float64, error) {
	panic("implement me")
}

func (Memory) RemoveSortedSetRange(s string, s2 string, s3 string) error {
	panic("implement me")
}

func (Memory) GetListRange(s string, i int64, i2 int64) ([]string, error) {
	panic("implement me")
}

func (Memory) RemoveFromList(s string, s2 string) error {
	panic("implement me")
}

func (Memory) AppendToSet(s string, s2 string) {
	panic("implement me")
}

func (m *Memory) Exists(key string) (bool, error) {
	_, err := m.db.Get(m.fixKey(key))
	if err != nil {
		return false, nil
	}
	return true, nil
}
