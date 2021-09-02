package main

import (
	"bytes"
	"encoding/json"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcd/wire"
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

func (k *Key) EncodePub(compress bool) (address string, err error) {
	pubKey, err := btcec.ParsePubKey(k.bip32Key.Key, btcec.S256())
        return GeneratePubFromBytes(pubKey, compress)
}

// https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
// bip44 define the following 5 levels in BIP32 path:
// m / purpose' / coin_type' / account' / change / address_index

func (k *Key) GetPath() string {
	return k.path
}

// Derivation with Mnemonic
type KeyManager struct {
	mnemonic   string
	passphrase string
	keys       map[string]*bip32.Key
	mux        sync.Mutex
}

// Derivation with XPRIV
type KeyMgr struct {
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


// Derivation from Mnemonic
func (km *KeyManager) getKey(path string) (*bip32.Key, bool) {
	km.mux.Lock()
	defer km.mux.Unlock()

	key, ok := km.keys[path]
	return key, ok
}

// Derivation from XPRIV
func (km *KeyMgr) getKey(path string) (*bip32.Key, bool) {
        km.mux.Lock()
        defer km.mux.Unlock()

        key, ok := km.keys[path]
        return key, ok
}

// Derivation from Mnemonic
func (km *KeyManager) setKey(path string, key *bip32.Key) {
	km.mux.Lock()
	defer km.mux.Unlock()

	km.keys[path] = key
}

// Derivation from XPRIV
func (km *KeyMgr) setKey(path string, key *bip32.Key) {
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

	if err != nil {
		return nil, err
	}

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

func (km *KeyMgr) GetAccountKeyFromXpriv(xpriv string) (*bip32.Key, error) {
        path := fmt.Sprintf(`XPRIV`)

        key, ok := km.getKey(path)
        if ok {
                return key, nil
        }

        key, err := bip32.B58Deserialize(xpriv)
        if err != nil {
                return nil, err
        }

        km.setKey(path, key)

        return key, nil
}


func (km *KeyMgr) GetAccountKeyFromXpub(xpub string) (*bip32.Key, error) {
        path := fmt.Sprintf(`XPUB`)

        key, ok := km.getKey(path)
        if ok {
                return key, nil
        }

        key, err := bip32.B58Deserialize(xpub)
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
func (km *KeyMgr) GetChangeKeyFromXpriv(xpriv string, change uint32) (*bip32.Key, error) {
	path := fmt.Sprintf(`XPRIV/%d`, change)

	key, ok := km.getKey(path)
	if ok {
		return key, nil
	}

	parent, err := km.GetAccountKeyFromXpriv(xpriv)
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

// GetChangeKey ...
// https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki#change
// change constant 0 is used for external chain
// change constant 1 is used for internal chain (also known as change addresses)
func (km *KeyMgr) GetChangeKeyFromXpub(xpub string, change uint32) (*bip32.Key, error) {
        path := fmt.Sprintf(`XPUB/%d`, change)

        key, ok := km.getKey(path)
        if ok {
                return key, nil
        }

        parent, err := km.GetAccountKeyFromXpub(xpub)
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


func (km *KeyMgr) GetKeyFromXpriv(xpriv string, change, index uint32) (*Key, error) {
	path := fmt.Sprintf(`XPRIV/%d/%d`, change, index)

	key, ok := km.getKey(path)
	if ok {
		return &Key{path: path, bip32Key: key}, nil
	}

	parent, err := km.GetChangeKeyFromXpriv(xpriv, change)
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

func (km *KeyMgr) GetKeyFromXpub(xpub string, change, index uint32) (*Key, error) {
        path := fmt.Sprintf(`XPUB/%d/%d`, change, index)

        key, ok := km.getKey(path)
        if ok {
                return &Key{path: path, bip32Key: key}, nil
        }

        parent, err := km.GetChangeKeyFromXpub(xpub, change)
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

func GeneratePubFromBytes(pubKey *btcec.PublicKey, compress bool) (address string, err error) {
	// generate a normal p2wkh address from the pubkey hash
        serializedPubKey := pubKey.SerializeCompressed()
        witnessProg := btcutil.Hash160(serializedPubKey)
        addressWitnessPubKeyHash, err := btcutil.NewAddressWitnessPubKeyHash(witnessProg, &chaincfg.MainNetParams)
        if err != nil {
                return "", err
        }
        address = addressWitnessPubKeyHash.EncodeAddress()

        return address, nil
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

// We don't host any Service for Bitcoin TESTNET at Relai.
// Therefore, we are going to use the API at blockstream.info instead.
// The interface is the same, it's just the URL that changes.
func LoadTestnetUtxos(address string) []Utxo {
        url := "https://blockstream.info/testnet/api/address/" + address + "/utxo"

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

// ========================================
// CRAFTING TRANSACTIONS (helper functions)
// ========================================

// Pass UTXO if you want to RBF, otherwise just pass nil (function will also return the used UTXO, for RBF purposes)
func CreateRawTx(utxo Utxo, from string, to string, amountInSats int, feeInSats int) (*wire.MsgTx, string, error) {
	spendAmount := amountInSats + feeInSats

	changeAmount := utxo.Value - spendAmount
	if changeAmount < 0 {
		fmt.Printf("Utxo contains %d sats. Trying to spend %d sats and %d sats in fees is not possible.\n", utxo.Value, amountInSats, feeInSats)
                return nil, "", errors.New("UTXO doesn't contain enough coins")
	}

	// create new empty transaction
	tx := wire.NewMsgTx(wire.TxVersion)
	
	// create single txIn
	hash, err := chainhash.NewHashFromStr(utxo.Txid)
	if err != nil {
		fmt.Printf("could not get hash from transaction ID: %v", err)
		return nil, "", err
	}

	outPoint := wire.NewOutPoint(hash, uint32(utxo.Vout))
	txIn := wire.NewTxIn(outPoint, nil, nil)
	txIn.Sequence = 4294967293 // Signal BIP 125 Replace-By-Fee
	tx.AddTxIn(txIn)
	fmt.Printf("TxID for TxIn: %s, index %d \n", utxo.Txid, utxo.Vout)

	// create TxOut
	// In the case of Relai, we'll often have to add MULTIPLE txOuts.
	rcvScript := GetTxScript(to)
	txOut := wire.NewTxOut(int64(amountInSats), rcvScript)
	tx.AddTxOut(txOut)
  
	// create TxOut for change address, in this case, change address is sender itself
	if changeAmount > 0 {
		// return change BTC to its own address
		rcvChangeAddressScript := GetTxScript(from) // todo other change address
		txOut := wire.NewTxOut(int64(changeAmount), rcvChangeAddressScript)
		tx.AddTxOut(txOut)
	}

	rcvScriptHex := hex.EncodeToString(rcvScript)

	return tx, rcvScriptHex, nil
}

func JsonEncodeTransaction(tx *wire.MsgTx) (string, error) {
	encodedTx, err := json.Marshal(tx)
        if err != nil {
                return "", err
        }

        return string(encodedTx), nil
}

func GetTxScript(addressStr string) []byte {
	// Parse the address to send the coins to into a btcutil.Address
        // which is useful to ensure the accuracy of the address and determine
        // the address type.  It is also required for the upcoming call to
        // PayToAddrScript.
	address, err := btcutil.DecodeAddress(addressStr, &chaincfg.TestNet3Params) // todo: change to &chaincfg.MainNetParams for MAINNET
        if err != nil {
                fmt.Println(err)
                return nil
        }

        // Create a public key script that pays to the address.
        script, err := txscript.PayToAddrScript(address)
        if err != nil {
                fmt.Println(err)
                return nil
        }
        fmt.Printf("Script Hex: %x\n", script)

        disasm, err := txscript.DisasmString(script)
        if err != nil {
                fmt.Println(err)
                return nil
        }
        fmt.Println("Script Disassembly:", disasm)

	return script
}

func SignTx(privKey string, pkScript string, redeemTx *wire.MsgTx, availableAmtInSats int) (string, int, error) {

   wif, err := btcutil.DecodeWIF(privKey)
   if err != nil {
      return "", 0, err
   }

   fmt.Println("privkey [wif]: ", wif)
   fmt.Println("wif.PrivKey: ", wif.PrivKey)

   sourcePKScript, err := hex.DecodeString(pkScript)
   if err != nil {
      return "", 0, err
   }

   // WitnessSignature(tx *wire.MsgTx, sigHashes *TxSigHashes, idx int, amt int64, subscript []byte, hashType SigHashType, privKey *btcec.PrivateKey, compress bool)
   signature, err := txscript.WitnessSignature(redeemTx, txscript.NewTxSigHashes(redeemTx), 0, int64(availableAmtInSats), sourcePKScript, txscript.SigHashAll, wif.PrivKey, true)
   if err != nil {
      return "", 0, err
   }

   // since there is only one input, and want to add
   // signature to it use 0 as index
//   redeemTx.TxIn[0].SignatureScript = signature
   redeemTx.TxIn[0].Witness = signature

   var signedTx bytes.Buffer
   redeemTx.Serialize(&signedTx)

   signedTxBytes := signedTx.Bytes()
   hexSignedTx := hex.EncodeToString(signedTxBytes)

   return hexSignedTx, len(signedTxBytes), nil
}

// We don't host any Service for Bitcoin TESTNET at Relai.
// Therefore, we are going to use the API at blockstream.info instead.
// The interface is the same, it's just the URL that changes.
func BroadcastTx(txHex string) (string) {
   // MAINNET --> url := "https://bitcoin.relai.ch/tx"
    url := "https://blockstream.info/testnet/api/tx"

    fmt.Printf("\nBroadcasting transaction to %s ... \n", url)

    body := []byte(txHex)
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    fmt.Println("response Status:", resp.Status)
    // fmt.Println("response Headers:", resp.Header)
    recvBody, _ := ioutil.ReadAll(resp.Body)
    txid := string(recvBody)
    fmt.Println("response Body [Transaction ID if request was successful]:", txid)

    return txid
}

type TxStatus struct {
        Confirmed    bool
        BlockHeight  int
        BlockHash    string
        BlockTime    int
}

// We don't host any Service for Bitcoin TESTNET at Relai.
// Therefore, we are going to use the API at blockstream.info instead.
// The interface is the same, it's just the URL that changes.
func CheckTxInBlock(txid string) (bool) {
	// MAINNET --> url := "https://bitcoin.relai.ch/tx" + txid + "/status"
	url := "https://blockstream.info/testnet/api/tx/" + txid + "/status"

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

        var txStatus TxStatus 
        jsonErr := json.Unmarshal([]byte(body), &txStatus)
        if jsonErr != nil {
                log.Fatal(jsonErr)
        }

        return txStatus.Confirmed
}

func main() {

	/* Starting from MNEMONIC

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

	*/

	/* Starting from XPRIV/XPUB key pair */

	// account xpub/xpriv from mnemonic "afford invest lady negative mango left hurdle three tragic short outside gentle dawn combine action obvious ready move dune reduce puppy nature choice diagram", password "chooseYourPassword", path "m/84'/0'/0'"
	xpriv := "zprvAcwXfubDhdV82hUAQeZcHgPmgvv9UkSx6nbEbz1YhkGtUZKiL8oDHqDj5Kov4mNRmEe4d6nzfq2jAzbByfdhoLAiHLZRXRZ2mPukWypCm1q" 
	xpub := "zpub6qvt5R87Y13RFBYdWg6cepLWExkdtDAoU1WqQNRAG5osMMersg7TqdYCvb5X734c8TpvAAGpk8xsENze5UcGuu4dCv58d3gioyNB9Pb8hiX"
	// ^ this is a 'key pair'. The xpub and xpriv belong to eachother. The xpub can be derived from the xpriv. The xpriv *cannot* be derived rom the xpub.
	// Both xpriv and xpub derive the same addresses, given the same derivation path, but private keys can only be derived from the xpriv.

	km := &KeyMgr{
                keys: make(map[string]*bip32.Key, 0),
        }

	fmt.Println("\nADDRESSES FOR DEPOSITS")
	fmt.Println(strings.Repeat("-", 114))
	fmt.Printf("%-18s %-42s %s\n", "Path(BIP84)", "SegWit(bech32)", "WIF(Wallet Import Format)")
	fmt.Println(strings.Repeat("-", 114))
	for i := 0; i < 10; i++ {
		key, err := km.GetKeyFromXpriv(xpriv, 0, uint32(i))
		if err != nil {
			log.Fatal(err)
		}
		wif, address, err := key.Encode(true)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%-18s %s %s\n", key.GetPath(), address, wif)
	}

	fmt.Println("\nADDRESSES FOR CHANGE")
        fmt.Println(strings.Repeat("-", 114))
        fmt.Printf("%-18s %-42s %s\n", "Path(BIP84)", "SegWit(bech32)", "WIF(Wallet Import Format)")
        fmt.Println(strings.Repeat("-", 114))
        for i := 0; i < 10; i++ {
                key, err := km.GetKeyFromXpriv(xpriv, 1, uint32(i))
                if err != nil {
                        log.Fatal(err)
                }
                wif, address, err := key.Encode(true)
                if err != nil {
                        log.Fatal(err)
                }

                fmt.Printf("%-18s %s %s\n", key.GetPath(), address, wif)
        }

        fmt.Println("\nDEPOSIT ADDRESSES DERIVED FROM XPUB")
        fmt.Println(strings.Repeat("-", 114))
        fmt.Printf("%-18s %-42s %s\n", "Path(BIP84)", "SegWit(bech32)", "WIF(Wallet Import Format)")
        fmt.Println(strings.Repeat("-", 114))
        for i := 0; i < 10; i++ {
                key, err := km.GetKeyFromXpub(xpub, 0, uint32(i))

                if err != nil {
                        log.Fatal(err)
                }
                address, err := key.EncodePub(true)
                if err != nil {
                        log.Fatal(err)
                }

                fmt.Printf("%-18s %s %s\n", key.GetPath(), address, "[can't be derived]")
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
		
		// Derivation from Mnemonic
		// key, err := km.GetKey(PurposeBIP84, CoinTypeBTC, 0, 0, uint32(i))
		
		// Derivation from XPRIV
		key, err := km.GetKeyFromXpriv(xpriv, 0, uint32(i))

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

	// =====================
        // CRAFTING TRANSACTIONS
        // =====================

	fmt.Println("\nCRAFT A TRANSACTION")

	sendingAddress := "tb1qx03jk6rwpxkm0dy8mdx6yk06mj0a5m6q7ws5p6"
	sendingPrivKey := "cPhJw9tQuE7Y61MCm8NJRgEjUwuV9mPL2SD3gJbRHn4maunEQKCW"
	receivingAddress := "tb1qx03jk6rwpxkm0dy8mdx6yk06mj0a5m6q7ws5p6"
	
	amtInSats := 1234567
        feeInSats := 200
	totalAmtInSats := amtInSats + feeInSats

	// For this demo, let's get read the amtInSats (value of UTXO in sats) from the TESTNET blockchain
	testnetUtxos := LoadTestnetUtxos(sendingAddress)
	if len(testnetUtxos) == 0 {
                fmt.Printf("Cannot find any UTXO for address %s.\n", sendingAddress)
                log.Fatal(errors.New("No UTXOs found"))
        }
        totalAmtInSats = testnetUtxos[0].Value
	amtInSats = totalAmtInSats - feeInSats

	fmt.Printf("Lookup UTXOs for address: %s\n", sendingAddress)

        utxos = LoadTestnetUtxos(sendingAddress)

        if len(utxos) == 0 {
                fmt.Printf("Cannot find any UTXO for address %s.\n", sendingAddress)
                log.Fatal(errors.New("No UTXOs found"))
        }

	rawTx, pkScript, err := CreateRawTx(utxos[0], sendingAddress, receivingAddress, amtInSats, feeInSats)
	
	if err != nil {
        	log.Fatal(err)
        }

	jsonEncodedRawTx, _ := JsonEncodeTransaction(rawTx)
	fmt.Printf("\nRaw Transaction: %s\n", jsonEncodedRawTx)
	fmt.Printf("\nPK Script: %s\n", pkScript)

	// Signing
	signedTx, txSize, _ := SignTx(sendingPrivKey, pkScript, rawTx, totalAmtInSats)
	fmt.Printf("\nSigned Transaction [Hex]: %s", signedTx)
	fmt.Printf("\nSigned Transaction Size: %d\n", txSize)

	// Broadcasting
	txid := BroadcastTx(signedTx)


	// Replace-by-fee
	minRelayFee := 1; // 1 is the default, leave it like that.

	// Always remember rules 3-5 from https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki#implementation-details :
	// 3) The replacement transaction pays an absolute fee of at least the sum paid by the original transactions.
	// 4) The replacement transaction must also pay for its own bandwidth at or above the rate set by the node's minimum relay fee setting. For example, if the minimum relay fee is 1 satoshi/byte and the replacement transaction is 500 bytes total, then the replacement must pay a fee at least 500 satoshis higher than the sum of the originals.
	// 5)The number of original transactions to be replaced and their descendant transactions which will be evicted from the mempool must not exceed a total of 100 transactions.


	intervalBetweenRbfReplacementsSecs := 30

	fmt.Printf("\n=============== RBF ===============\n")
        fmt.Printf("Replacing tx with higher fee every %d seconds (RBF)\n", int(intervalBetweenRbfReplacementsSecs))
        fmt.Printf("Original fee in sats: %d\n\n", feeInSats)
        time.Sleep(time.Duration(intervalBetweenRbfReplacementsSecs) * time.Second)

	// For the fun of it, let's fee-bump our tx every 30 seconds, until it is mined into a block. (Transaction may be replaced up to 100 times.)
	for !CheckTxInBlock(txid) {

		// Rule nr. 4
		feeBumpAmt := txSize * minRelayFee
		feeInSats = feeInSats + feeBumpAmt // minimal fee increase. Can always be more than that.
		amtInSats = amtInSats - feeBumpAmt
		// ^ Since we are paying more in fees the money we're paying more must be missing in another output.
		// In this simple example transaction, we just shrink the amount the receiver of the transaction gets.
		// In regular cases (and Relai's case too), you'd have a change address, which would shrink with rising transaction fees.

		// Craft transaction again, but with higher fee:
		rawTx, pkScript, err = CreateRawTx(utxos[0], sendingAddress, receivingAddress, amtInSats, feeInSats)
		jsonEncodedRawTx, _ = JsonEncodeTransaction(rawTx)
		signedTx, txSize, _ = SignTx(sendingPrivKey, pkScript, rawTx, totalAmtInSats)
        	fmt.Printf("\nRBF Signed Transaction [Hex]: %s", signedTx)
	        fmt.Printf("\nRBF Signed Transaction Size: %d\n", txSize)

        	// Broadcasting
	        txid = BroadcastTx(signedTx)

		fmt.Printf("\nBroadcasted RBF transaction with paying %d sats in fees\n", feeInSats)

		time.Sleep(time.Duration(intervalBetweenRbfReplacementsSecs) * time.Second)
	}

	fmt.Println("Transaction is now confirmed. Txid:", txid)
}
