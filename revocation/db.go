package revocation

import (
	"time"

	"github.com/coreos/bbolt"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/signed"
	"github.com/timshannon/bolthold"
)

type (
	// Keystore provides support for revocation public key rollover.
	Keystore interface {
		// PublicKey either returns the specified, non-nil public key or an error
		PublicKey(counter uint) (*PublicKey, error)
	}

	// DB is a bolthold database storing revocation state for a particular accumulator
	// (Record instances, and IssuanceRecord instances if used by an issuer).
	DB struct {
		Current  Accumulator
		bolt     *bolthold.Store
		keystore Keystore
	}

	// Record contains a signed AccumulatorUpdate and associated information.
	Record struct {
		StartIndex     uint64
		EndIndex       uint64
		PublicKeyIndex uint
		Message        signed.Message
	}

	// IssuanceRecord contains information generated during issuance, needed for later revocation.
	IssuanceRecord struct {
		Key        string
		Attr       *big.Int
		Issued     int64
		ValidUntil int64
		RevokedAt  int64 // 0 if not currently revoked
	}

	currentRecord struct {
		Index uint64
	}
)

func LoadDB(path string, keystore Keystore) (*DB, error) {
	b, err := bolthold.Open(path, 0600, &bolthold.Options{Options: &bolt.Options{Timeout: 1 * time.Second}})
	if err != nil {
		return nil, err
	}
	return &DB{
		bolt:     b,
		keystore: keystore,
	}, nil
}

func (rdb *DB) EnableRevocation(sk *PrivateKey) error {
	msg, acc, err := NewAccumulator(sk)
	if err != nil {
		return err
	}
	if err = rdb.Add(msg, sk.Counter); err != nil {
		return err
	}
	rdb.Current = acc
	return nil
}

// Revoke revokes the credential specified specified by key if found within the current database,
// by updating its revocation time to now, adding its revocation attribute to the current accumulator,
// and updating the revocation database on disk.
func (rdb *DB) Revoke(sk *PrivateKey, key []byte) error {
	return rdb.bolt.Bolt().Update(func(tx *bolt.Tx) error {
		var err error
		cr := IssuanceRecord{}
		if err = rdb.bolt.TxGet(tx, key, &cr); err != nil {
			return err
		}
		cr.RevokedAt = time.Now().UnixNano()
		if err = rdb.bolt.TxUpdate(tx, key, &cr); err != nil {
			return err
		}
		return rdb.revokeAttr(sk, cr.Attr, tx)
	})
}

// Get returns all records that a client requires to update its revocation state if it is currently
// at the specified index, that is, all records whose end index is greater than or equal to
// the specified index.
func (rdb *DB) RevocationRecords(index int) ([]Record, error) {
	var err error
	var records []Record
	if err = rdb.bolt.Find(&records, bolthold.Where(bolthold.Key).Ge(uint64(index))); err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("not found")
	}
	return records, nil
}

func (rdb *DB) LatestRecords(count int) ([]Record, error) {
	c := int(rdb.Current.Index) - count + 1
	if c < 0 {
		c = 0
	}
	return rdb.RevocationRecords(c)
}

func (rdb *DB) KeyExists(key []byte) (bool, error) {
	_, err := rdb.IssuanceRecord(key)
	switch err {
	case nil:
		return true, nil
	case bolthold.ErrNotFound:
		return false, nil
	default:
		return false, err
	}
}

func (rdb *DB) AddIssuanceRecord(r *IssuanceRecord) error {
	return rdb.bolt.Insert([]byte(r.Key), r)
}

func (rdb *DB) IssuanceRecord(key []byte) (*IssuanceRecord, error) {
	r := &IssuanceRecord{}
	if err := rdb.bolt.Get(key, r); err != nil {
		return nil, err
	}
	return r, nil
}

func (rdb *DB) Add(updateMsg signed.Message, counter uint) error {
	var err error
	var update AccumulatorUpdate

	pk, err := rdb.keystore.PublicKey(counter)
	if err != nil {
		return err
	}

	if err = signed.UnmarshalVerify(pk.ECDSA, updateMsg, &update); err != nil {
		return err
	}

	return rdb.bolt.Bolt().Update(func(tx *bolt.Tx) error {
		return rdb.add(update, updateMsg, counter, tx)
	})
}

const boltCurrentIndexKey = "currentIndex"

func (rdb *DB) add(update AccumulatorUpdate, updateMsg signed.Message, pkCounter uint, tx *bolt.Tx) error {
	var err error
	if err = rdb.bolt.TxInsert(tx, update.Accumulator.Index, &Record{
		StartIndex:     update.StartIndex,
		EndIndex:       update.Accumulator.Index,
		PublicKeyIndex: pkCounter,
		Message:        updateMsg,
	}); err != nil {
		return err
	}
	if err = rdb.bolt.TxUpsert(tx, boltCurrentIndexKey, &currentRecord{update.Accumulator.Index}); err != nil {
		return err
	}

	rdb.Current = update.Accumulator
	return nil
}

func (rdb *DB) Enabled() bool {
	var currentIndex currentRecord
	err := rdb.bolt.Get(boltCurrentIndexKey, &currentIndex)
	return err == nil
}

func (rdb *DB) LoadCurrent() error {
	var currentIndex currentRecord
	if err := rdb.bolt.Get(boltCurrentIndexKey, &currentIndex); err == bolthold.ErrNotFound {
		return errors.New("revocation database not initialized")
	} else if err != nil {
		return err
	}

	var record Record
	if err := rdb.bolt.Get(currentIndex.Index, &record); err != nil {
		return err
	}
	pk, err := rdb.keystore.PublicKey(record.PublicKeyIndex)
	if err != nil {
		return err
	}
	var u AccumulatorUpdate
	if err = signed.UnmarshalVerify(pk.ECDSA, record.Message, &u); err != nil {
		return err
	}
	rdb.Current = u.Accumulator
	return nil
}

func (rdb *DB) revokeAttr(sk *PrivateKey, e *big.Int, tx *bolt.Tx) error {
	// don't update rdb.Current until after all possible errors are handled
	newAcc, err := rdb.Current.Remove(sk, e)
	if err != nil {
		return err
	}
	update := AccumulatorUpdate{
		Accumulator: *newAcc,
		StartIndex:  newAcc.Index,
		Revoked:     []*big.Int{e},
		Time:        time.Now().UnixNano(),
	}
	updateMsg, err := signed.MarshalSign(sk.ECDSA, update)
	if err != nil {
		return err
	}
	if err = rdb.add(update, updateMsg, sk.Counter, tx); err != nil {
		return err
	}
	rdb.Current = *newAcc
	return nil
}

func (rdb *DB) Close() error {
	if rdb.bolt != nil {
		return rdb.bolt.Close()
	}
	return nil
}

func (r *Record) UnmarshalVerify(keystore Keystore) (*AccumulatorUpdate, error) {
	pk, err := keystore.PublicKey(r.PublicKeyIndex)
	if err != nil {
		return nil, err
	}
	msg := &AccumulatorUpdate{}
	if err := signed.UnmarshalVerify(pk.ECDSA, r.Message, msg); err != nil {
		return nil, err
	}
	return msg, nil
}
