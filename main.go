package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

// Purpose BIP43 - Purpose Field for Deterministic Wallets
// https://github.com/bitcoin/bips/blob/master/bip-0043.mediawiki
//
// Purpose is a constant set to 44' (or 0x8000002C) following the BIP43 recommendation.
// It indicates that the subtree of this node is used according to this specification.
//
// What does 44' mean in BIP44?
// https://bitcoin.stackexchange.com/questions/74368/what-does-44-mean-in-bip44
//
// 44' means that hardened keys should be used. The distinguisher for whether
// a key a given index is hardened is that the index is greater than 2^31,
// which is 2147483648. In hex, that is 0x80000000. That is what the apostrophe (') means.
// The 44 comes from adding it to 2^31 to get the final hardened key index.
// In hex, 44 is 2C, so 0x80000000 + 0x2C = 0x8000002C.
type Purpose = uint32

const (
	PurposeBIP44 Purpose = 0x8000002C // 44' BIP44
	PurposeBIP49 Purpose = 0x80000031 // 49' BIP49
	PurposeBIP84 Purpose = 0x80000054 // 84' BIP84
)

// CoinType SLIP-0044 : Registered coin types for BIP-0044
// https://github.com/satoshilabs/slips/blob/master/slip-0044.md
type CoinType = uint32

const (
	CoinTypeBTC CoinType = 0x80000000  // MAINNET
	CoinTypeTBTC CoinType = 0x80000001 // TESTNET
)

const (
	Apostrophe uint32 = 0x80000000 // 0'
)

type Key struct {
	path     string
	bip32Key *bip32.Key
}

func (k *Key) Encode(compress bool) (wif, address string, err error) {
	prvKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), k.bip32Key.Key)
	return GenerateFromBytes(prvKey, compress)
}

// https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
// bip44 define the following 5 levels in BIP32 path:
// m / purpose' / coin_type' / account' / change / address_index

func (k *Key) GetPath() string {
	return k.path
}

type KeyManager struct {
	mnemonic   string
	passphrase string
	keys       map[string]*bip32.Key
	mux        sync.Mutex
}

// NewKeyManager return new key manager
// bitSize has to be a multiple 32 and be within the inclusive range of {128, 256}
// 128: 12 phrases
// 256: 24 phrases
func NewKeyManager(bitSize int, passphrase, mnemonic string) (*KeyManager, error) {

	if mnemonic == "" {
		entropy, err := bip39.NewEntropy(bitSize)
		if err != nil {
			return nil, err
		}
		mnemonic, err = bip39.NewMnemonic(entropy)
		if err != nil {
			return nil, err
		}
	}

	km := &KeyManager{
		mnemonic:   mnemonic,
		passphrase: passphrase,
		keys:       make(map[string]*bip32.Key, 0),
	}
	return km, nil
}

func (km *KeyManager) GetMnemonic() string {
	return km.mnemonic
}

func (km *KeyManager) GetPassphrase() string {
	return km.passphrase
}

func (km *KeyManager) GetSeed() []byte {
	return bip39.NewSeed(km.GetMnemonic(), km.GetPassphrase())
}

func (km *KeyManager) getKey(path string) (*bip32.Key, bool) {
	km.mux.Lock()
	defer km.mux.Unlock()

	key, ok := km.keys[path]
	return key, ok
}

func (km *KeyManager) setKey(path string, key *bip32.Key) {
	km.mux.Lock()
	defer km.mux.Unlock()

	km.keys[path] = key
}

func (km *KeyManager) GetMasterKey() (*bip32.Key, error) {
	path := "m"

	key, ok := km.getKey(path)
	if ok {
		return key, nil
	}

	key, err := bip32.NewMasterKey(km.GetSeed())
	if err != nil {
		return nil, err
	}

	keyOneLevelDown, err := key.NewChildKey(0)
	if err != nil {
		return nil, err
	}
	fmt.Println("One level down: %s", keyOneLevelDown)

	km.setKey(path, key)

	return key, nil
}

func (km *KeyManager) GetPurposeKey(purpose uint32) (*bip32.Key, error) {
	path := fmt.Sprintf(`m/%d'`, purpose-Apostrophe)

	key, ok := km.getKey(path)
	if ok {
		return key, nil
	}

	parent, err := km.GetMasterKey()
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(purpose)
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return key, nil
}

func (km *KeyManager) GetCoinTypeKey(purpose, coinType uint32) (*bip32.Key, error) {
	path := fmt.Sprintf(`m/%d'/%d'`, purpose-Apostrophe, coinType-Apostrophe)

	key, ok := km.getKey(path)
	if ok {
		return key, nil
	}

	parent, err := km.GetPurposeKey(purpose)
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(coinType)
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return key, nil
}

func (km *KeyManager) GetAccountKey(purpose, coinType, account uint32) (*bip32.Key, error) {
	path := fmt.Sprintf(`m/%d'/%d'/%d'`, purpose-Apostrophe, coinType-Apostrophe, account)

	key, ok := km.getKey(path)
	if ok {
		return key, nil
	}

	parent, err := km.GetCoinTypeKey(purpose, coinType)
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(account + Apostrophe)
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return key, nil
}

// GetChangeKey ...
// https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki#change
// change constant 0 is used for external chain
// change constant 1 is used for internal chain (also known as change addresses)
func (km *KeyManager) GetChangeKey(purpose, coinType, account, change uint32) (*bip32.Key, error) {
	path := fmt.Sprintf(`m/%d'/%d'/%d'/%d`, purpose-Apostrophe, coinType-Apostrophe, account, change)

	key, ok := km.getKey(path)
	if ok {
		return key, nil
	}

	parent, err := km.GetAccountKey(purpose, coinType, account)
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(change)
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return key, nil
}

func (km *KeyManager) GetKey(purpose, coinType, account, change, index uint32) (*Key, error) {
	path := fmt.Sprintf(`m/%d'/%d'/%d'/%d/%d`, purpose-Apostrophe, coinType-Apostrophe, account, change, index)

	key, ok := km.getKey(path)
	if ok {
		return &Key{path: path, bip32Key: key}, nil
	}

	parent, err := km.GetChangeKey(purpose, coinType, account, change)
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(index)
	if err != nil {
		return nil, err
	}

	km.setKey(path, key)

	return &Key{path: path, bip32Key: key}, nil
}

func Generate(compress bool) (wif, address string, err error) {
	prvKey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return "", "", err
	}
	return GenerateFromBytes(prvKey, compress)
}

func GenerateFromBytes(prvKey *btcec.PrivateKey, compress bool) (wif, address string, err error) {
	// generate the wif(wallet import format) string
	btcwif, err := btcutil.NewWIF(prvKey, &chaincfg.MainNetParams, compress)
	if err != nil {
		return "", "", err
	}
	wif = btcwif.String()

	// generate a normal p2wkh address from the pubkey hash
	serializedPubKey := btcwif.SerializePubKey()
	witnessProg := btcutil.Hash160(serializedPubKey)
	addressWitnessPubKeyHash, err := btcutil.NewAddressWitnessPubKeyHash(witnessProg, &chaincfg.MainNetParams)
	if err != nil {
		return "", "", err
	}
	address = addressWitnessPubKeyHash.EncodeAddress()

	return wif, address, nil
}

type Utxo struct {
	Txid   string
	Vout   int
	Status UtxoStatus
	Value  int
}

type UtxoStatus struct {
	Confirmed    bool
	Block_height int
	Block_hash   string
	Block_time   int
}

func LoadUtxos(address string) []Utxo {
	url := "https://bitcoin.relai.ch/address/" + address + "/utxo"

	spaceClient := http.Client{
		Timeout: time.Second * 2, // Timeout after 2 seconds
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("User-Agent", "spacecount-tutorial")

	res, getErr := spaceClient.Do(req)
	if getErr != nil {
		log.Fatal(getErr)
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		log.Fatal(readErr)
	}

	var utxos []Utxo
	jsonErr := json.Unmarshal([]byte(body), &utxos)
	if jsonErr != nil {
		log.Fatal(jsonErr)
	}

	return utxos
}

func main() {
	// BIP39 MNEMONIC
	passphrase := "chooseYourPassword"
	km, err := NewKeyManager(256, passphrase, "")
	//km, err := NewKeyManager(256, passphrase, "afford invest lady negative mango left hurdle three tragic short outside gentle dawn combine action obvious ready move dune reduce puppy nature choice diagram") // optionally reuse an existing mnemonic

	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("\n%-18s %s\n", "BIP39 Mnemonic:", km.GetMnemonic())
	fmt.Printf("%-18s %x\n", "BIP39 Seed:", km.GetSeed())     // Only for the record. Not needed for Relai's purposes
	fmt.Printf("%-18s %s\n", "BIP39 Passphrase:", passphrase) // Only for the record. Not needed for Relai's purposes

	fmt.Println("\nADDRESSES FOR DEPOSITS FROM EXCHANGE")
	fmt.Println(strings.Repeat("-", 114))
	fmt.Printf("%-18s %-42s %s\n", "Path(BIP84)", "SegWit(bech32)", "WIF(Wallet Import Format)")
	fmt.Println(strings.Repeat("-", 114))
	for i := 0; i < 10; i++ {
		key, err := km.GetKey(PurposeBIP84, CoinTypeBTC, 0, 0, uint32(i))
		if err != nil {
			log.Fatal(err)
		}
		wif, address, err := key.Encode(true)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%-18s %s %s\n", key.GetPath(), address, wif)
	}

	fmt.Println("\nADDRESSES FOR CHANGE, WHEN MONEY IS SENT TO EXCHANGE")
	fmt.Println(strings.Repeat("-", 114))
	fmt.Printf("%-18s %-42s %s\n", "Path(BIP84)", "SegWit(bech32)", "WIF(Wallet Import Format)")
	fmt.Println(strings.Repeat("-", 114))
	for i := 0; i < 10; i++ {
		key, err := km.GetKey(PurposeBIP84, CoinTypeBTC, 0, 1, uint32(i))
		if err != nil {
			log.Fatal(err)
		}
		wif, address, err := key.Encode(true)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%-18s %s %s\n", key.GetPath(), address, wif)
	}

	fmt.Println("\nADDRESSES FOR DEPOSITS FROM USERS")
	fmt.Println(strings.Repeat("-", 114))
	fmt.Printf("%-18s %-42s %s\n", "Path(BIP84)", "SegWit(bech32)", "WIF(Wallet Import Format)")
	fmt.Println(strings.Repeat("-", 114))
	for i := 0; i < 10; i++ {
		key, err := km.GetKey(PurposeBIP84, CoinTypeBTC, 1, 0, uint32(i))
		if err != nil {
			log.Fatal(err)
		}
		wif, address, err := key.Encode(true)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%-18s %s %s\n", key.GetPath(), address, wif)
	}

	fmt.Println("\nADDRESSES FOR CHANGE, WHEN MONEY IS SENT TO USERS")
	fmt.Println(strings.Repeat("-", 114))
	fmt.Printf("%-18s %-42s %s\n", "Path(BIP84)", "SegWit(bech32)", "WIF(Wallet Import Format)")
	fmt.Println(strings.Repeat("-", 114))
	for i := 0; i < 10; i++ {
		key, err := km.GetKey(PurposeBIP84, CoinTypeBTC, 1, 1, uint32(i))
		if err != nil {
			log.Fatal(err)
		}
		wif, address, err := key.Encode(true)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%-18s %s %s\n", key.GetPath(), address, wif)
	}
	fmt.Println()

	// =============================
	// LOAD UTXOS
	// =============================

	address := "bc1qgdjqv0av3q56jvd82tkdjpy7gdp9ut8tlqmgrpmv24sq90ecnvqqjwvw97"
	utxos := LoadUtxos(address)

	fmt.Println("\nGATHER UTXOs FROM BITCOIN.RELAI.CH")
	// Print entire unmarshaled JSON
	fmt.Printf("\nUnmarshaled:\n%v\n", utxos)

	fmt.Printf("\nNicely put sample UTXO:")
	fmt.Printf("\nTransaction id = %s", utxos[0].Txid)
	fmt.Printf("\nIndex of the output within the transaction = %d", utxos[0].Vout)
	fmt.Printf("\nAmount of Satoshis = %d", utxos[0].Value)
	fmt.Printf("\nTransaction is confirmed = %t", utxos[0].Status.Confirmed)
	fmt.Printf("\nConfirmed at block = %d", utxos[0].Status.Block_height)
	fmt.Printf("\nTime the block was mined = %d %s", utxos[0].Status.Block_time, "(not interesting for Relai's purposes)")
	fmt.Printf("\nHash of the block = %s %s", utxos[0].Status.Block_hash, "(not interesting for Relai's purposes)")
	fmt.Println("\n")

	// =============================
	// LOAD UTXOS FOR RELAI WALLET
	// =============================

	fmt.Println("\nUTXOs for Relai wallet (obviously, there are none)")
	fmt.Println(strings.Repeat("-", 79))
	fmt.Printf("%-18s %-44s %s\n", "Path(BIP84)", "SegWit(bech32)", "Amount of UTXOs")
	fmt.Println(strings.Repeat("-", 79))
	for i := 0; i < 10; i++ {
		key, err := km.GetKey(PurposeBIP84, CoinTypeBTC, 0, 0, uint32(i))
		if err != nil {
			log.Fatal(err)
		}
		_, address, err := key.Encode(true)
		if err != nil {
			log.Fatal(err)
		}

		utxos := LoadUtxos(address)

		fmt.Printf("%-18s %s \t%d\n", key.GetPath(), address, len(utxos))
	}
}

