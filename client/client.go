package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username string

	// filenames to uuid of file
	ownedFiles map[string]uuid.UUID
	// names of people who invited you to the invitation they sent you
	invitations map[string]uuid.UUID
	// TODO: figure out logic for keeping track of invitations sent out to users
	// invited map[(string,string)]uuid.UUID

	// filename to the invitation structure associated with it
	sharedFiles map[string]Invitation

	// private RSA key for user
	privateKey userlib.PrivateKeyType

	// private Sign function for user
	privateSignKey userlib.DSSignKey

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type Invitation struct {
	// TODO ADD

}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	// check if empty username is provided
	if username == "" {
		panic(errors.New("An empty username was provided please provide username of length of at least 1"))
	}
	// check if a user with the username already exists
	userCheck := username + "RSA"
	_, ok := userlib.KeystoreGet(userCheck)
	if ok == true {
		panic(errors.New("The username already exists"))
	}
	//We initialize a new User struct here
	var userdata User
	userdata.Username = username

	// generate public + private key, assign private key
	var pubRSA userlib.PKEEncKey
	var priRSA userlib.PKEDecKey
	pubRSA, priRSA, _ = userlib.PKEKeyGen()
	userdata.privateKey = priRSA
	// storing the public key in KeyStore
	userlib.KeystoreSet(username+"RSA", pubRSA)

	// generate sign + verify signature key, assign sign key
	var priSign userlib.DSSignKey
	var pubSign userlib.DSVerifyKey
	priSign, pubSign, _ = userlib.DSKeyGen()
	userdata.privateSignKey = priSign
	// storing the verify key in Keystore
	userlib.KeystoreSet(username+"Sign", pubSign)

	//TODO MAYBE CHANGE HOW WE DEAL WITH SALTS????????
	salt := userlib.Hash([]byte(username))
	//Maybe change to something else to store the salt (maybe instide user struct or datastore)
	userByte := userlib.Argon2Key([]byte(username+password), salt, 16)
	userUUID, err := uuid.FromBytes(userByte)
	if err != nil {
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	//userdataByte is the User struct turned into a byte for storage
	userdataByte, err := json.Marshal(userdata)
	//Error message
	if err != nil {
		panic(errors.New("An error occurred while converting User struct to []bytes: " + err.Error()))
	}
	userlib.DatastoreSet(userUUID, userdataByte)

	// use the HASHKDF alonside the term "HMAC" to generate our HMAC key
	largeHash, err := userlib.HashKDF(userByte, []byte("HMAC"))
	if err != nil {
		return nil, err
	}
	//Calculate the HMAC of the User struct byte string
	HMACValue, err := userlib.HMACEval(largeHash[0:16], userdataByte)
	if err != nil {
		return nil, err
	}

	// generate UUID with hashed username + HMAC
	userHMAC := userlib.Hash([]byte(username + "HMAC"))
	HMACUUID, err := uuid.FromBytes(userHMAC[:16])
	// Store the HMAC'd user struct on dataStore
	userlib.DatastoreSet(HMACUUID, HMACValue)

	//TODO: Encrypt User Struct

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
