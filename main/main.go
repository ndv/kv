package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/ndv/kv/bitcurve"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
)

var (
	db *Database
)

func main() {
	portNumber := flag.Int("port", 8546, "Port number")
	flag.Parse()

	defaultPath := os.Getenv("HOME")
	if defaultPath == "" {
		defaultPath = "."
	}
	databasePath := flag.String("database", defaultPath + "/.kv/database", "Database path")
	flag.Parse()

	var err error
	db, err = NewDatabase(*databasePath)
	if err != nil {
		log.Fatal("Cannot open %s: %s", *databasePath, err.Error())
		return
	}
	defer db.Close()

	http.HandleFunc("/put", handlePut)
	http.HandleFunc("/getAll", handleGetAll)
	http.HandleFunc("/clear", handleClear)

	// Determine port for HTTP service.
	// Start HTTP main.
	log.Printf("Listening on port %d", *portNumber)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *portNumber), nil))
}

func readUint16(r *bufio.Reader) (uint16, error) {
	bytes := make([]byte, 2)
	_, err := io.ReadFull(r, bytes)
	if err == nil {
		return binary.LittleEndian.Uint16(bytes), nil
	}
	return 0, err
}

func writeUint16(i uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, i)
	return b
}

type CryptoContext struct {
	s, r   *big.Int
	pubkey *ecdsa.PublicKey
}

type WrongPubkeyError struct {}

func (e *WrongPubkeyError) Error() string {
	return "Wrong compressed public key"
}

func readRequestHeader(body *bufio.Reader) (*CryptoContext, error) {
	rbytes := make([]byte, 32)
	_, err := io.ReadFull(body, rbytes)
	if err == nil {
		sbytes := make([]byte, 32)
		_, err = io.ReadFull(body, sbytes)
		if err == nil {
			pubkeyBytes := make([]byte, 33)
			_, err = io.ReadFull(body, pubkeyBytes)
			if err == nil {
				pubkey := bitcurve.S256().UncompressPoint(pubkeyBytes)
				fmt.Println("Uncompressed point ", pubkey)
				if pubkey != nil {
					return &CryptoContext{s: new(big.Int).SetBytes(sbytes), r: new(big.Int).SetBytes(rbytes), pubkey: pubkey}, nil
				} else {
					err = &WrongPubkeyError{}
				}
			}
		}
	}
	return nil, err
}

func httpError(err error, w http.ResponseWriter) bool {
	if err == nil {
		return false
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(400)
		fmt.Fprintln(w, err.Error())
		fmt.Println("Error: ", err.Error())
		return true
	}
}

func (ctx *CryptoContext) checkSignature(message []byte) bool {
	hash := sha256.Sum256(message)
	return ecdsa.Verify(ctx.pubkey, hash[:], ctx.r, ctx.s)
}

func handlePut (w http.ResponseWriter, req *http.Request) {
	log.Printf("req=%s", req.URL)

	body := bufio.NewReader(req.Body)

	s := make([]byte, 32)
	_, err := io.ReadFull(body, s)
	if httpError(err, w) {
		return
	}
	r := make([]byte, 32)
	_, err = io.ReadFull(body, r)
	if httpError(err, w) {
		return
	}

	fmt.Println("s,r = ", s, r)

	ctx, err := readRequestHeader(body)
	if httpError(err, w) {
		return
	}
	ksize, err := readUint16(body)
	if httpError(err, w) {
		return
	}
	key := make([]byte, ksize)
	_, err = io.ReadFull(body, key)
	if httpError(err, w) {
		return
	}

	fmt.Println("key = ", key)

	vsize, err := readUint16(body)
	if httpError(err, w) {
		return
	}
	value := make([]byte, vsize)
	_, err = io.ReadFull(body, value)
	if httpError(err, w) {
		return
	}

	fmt.Println("value = ", value)

	message := append(writeUint16(ksize), key...)
	message = append(message, writeUint16(vsize)...)
	message = append(message, value...)

	if !ctx.checkSignature(message) {
		w.WriteHeader(403)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "Wrong signature")
	} else {
		db.Put(ctx.pubkey, key, value)
		w.WriteHeader(200)
	}
}

func handleGetAll (w http.ResponseWriter, req *http.Request) {
	log.Printf("req=%s", req.URL)

	body := bufio.NewReader(req.Body)

	ctx, err := readRequestHeader(body)
	if httpError(err, w) {
		return
	}

	list, err := db.GetAll(ctx.pubkey)
	if httpError(err, w) {
		return
	}

	w.WriteHeader(200)
	w.Header().Set("Content-Type", "application/json")

	fmt.Fprintln(w, "[")
	for i := 0; i < len(list); i++ {
		pair := list[i]
		if i != 0 {
			fmt.Fprintln(w, ",\n")
		}
		fmt.Fprintln(w, "{\"key\": \"")
		hex.NewEncoder(w).Write(pair.key)
		fmt.Fprintln(w, "\", \"value\": \"")
		hex.NewEncoder(w).Write(pair.value)
		fmt.Fprintln(w, "\"}")
	}
	fmt.Fprintln(w, "]")
}

func handleClear (w http.ResponseWriter, req *http.Request) {
	log.Printf("req=%s", req.URL)

	body := bufio.NewReader(req.Body)

	ctx, err := readRequestHeader(body)
	if httpError(err, w) {
		return
	}

	err = db.Clear(ctx.pubkey)
	if httpError(err, w) {
		return
	}
}
