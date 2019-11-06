package main

import (
	"crypto/ecdsa"
	"github.com/ndv/kv/bitcurve"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/filter"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
	"sync"
)

type Database struct {
	db       *leveldb.DB
	quitLock sync.Mutex      // Mutex protecting the quit channel access
}

func NewDatabase(path string) (*Database, error) {
	db, err := leveldb.OpenFile(path, &opt.Options{
		OpenFilesCacheCapacity: 256,
		BlockCacheCapacity:     256 / 2 * opt.MiB,
		WriteBuffer:            256 / 4 * opt.MiB, // Two of these are used internally
		Filter:                 filter.NewBloomFilter(10),
		DisableSeeksCompaction: true,
	})
	if _, corrupted := err.(*errors.ErrCorrupted); corrupted {
		db, err = leveldb.RecoverFile(path, nil)
	}
	if err != nil {
		return nil, err
	}
	// Assemble the wrapper with all the registered metrics
	return &Database{db: db}, nil
}

func (db *Database) Close() error {
	db.quitLock.Lock()
	defer db.quitLock.Unlock()
	return db.db.Close()
}

func (db *Database) Put(pubkey *ecdsa.PublicKey, key []byte, value []byte) error {
	key = append(bitcurve.CompressPoint(pubkey), key...)
	return db.db.Put(key, value, nil)
}

type Pair struct {
	key, value []byte
}

func (db *Database) GetAll(pubkey *ecdsa.PublicKey) ([]Pair, error) {
	prefix := bitcurve.CompressPoint(pubkey)
	iterator := db.db.NewIterator(util.BytesPrefix(prefix), nil)
	defer iterator.Release()
	if !iterator.First() {
		return make([]Pair, 0), nil
	}
	result := []Pair {Pair{iterator.Key(), iterator.Value()}}
	for iterator.Next() {
		result = append(result, Pair{iterator.Key(), iterator.Value()})
	}
	return result, nil
}

func (db *Database) Clear(pubkey *ecdsa.PublicKey) error {
	prefix := bitcurve.CompressPoint(pubkey)
	iterator := db.db.NewIterator(util.BytesPrefix(prefix), nil)
	defer iterator.Release()
	if !iterator.First() {
		return nil
	}
	err := db.db.Delete(iterator.Key(), nil)
	if err != nil {
		return err
	}
	for iterator.Next() {
		err = db.db.Delete(iterator.Key(), nil)
		if err != nil {
			return err
		}
	}
	return nil
}
