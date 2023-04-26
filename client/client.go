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

	Password string

	// Dict mapping filenames to uuid of file intermediate struct
	OwnedFiles map[string]uuid.UUID

	// Dict mapping filesnames to files invitations we were invited to and accepted
	InvitedFiles map[string]uuid.UUID

	// private RSA key for user
	PrivateKey userlib.PrivateKeyType

	// private Sign function for user
	PrivateSignKey userlib.DSSignKey

	// Map mapping file UUID to File Encrypt key
	FileEncrypt map[uuid.UUID][]byte

	// Map mapping file UUID to File HMAC key
	FileHMAC map[uuid.UUID][]byte

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type File struct {
	Content  []byte
	NextFile uuid.UUID
	// Only really comes into play for the header
	LastFile uuid.UUID
}

type Invitation struct {

	// Signature given to the invitation
	Signature []byte
	// RSA encrpyted UUID of the intermediate struct
	EncIntermediateUUID []byte
	// RSA mac key
	RSAMacKey []byte
	// RSA Encryption key
	RSAEncryptKey []byte
	// RSA macUUID key
	RSAMacUUID []byte
}

type InvitationIntermediate struct {

	//File Encrypt key
	FileEncryptKey []byte
	//File MAC key
	FileMACKey []byte
	//File head uuid
	FileHeadUUID uuid.UUID
	//HMACUUID salt (salt value for generation of HMAC keys)
	HMACUUIDSalt []byte
}

type FileIntermediate struct {
	// UUID of file
	FileUUID uuid.UUID

	// Dict that maps usernames to invitations (UUID of Intermediate struct above)
	UserInvitations map[string]uuid.UUID

	// File Encrypt Key
	FileEncrypt []byte

	// File MAC Key
	FileMac []byte

	// HMACUUID salt (salt value for generation of HMAC keys)
	HMACUUIDSalt []byte

	// Dict that maps usernames to Intermediate Encrypt key
	KeysIntermediateEncrypt map[string][]byte

	// Dict that maps usernames to Intermediate HMAC key
	KeysIntermediateHMAC map[string][]byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	// check if empty username is provided
	if username == "" {
		return nil, errors.New("An empty username was provided please provide username of length of at least 1")
	}
	// check if a user with the username already exists
	userCheck := username + "RSA"
	_, ok := userlib.KeystoreGet(userCheck)
	if ok == true {
		return nil, errors.New("The username already exists")
	}
	//We initialize a new User struct here
	var userdata User
	userdata.Username = username
	userdata.Password = password

	// generate public + private key, assign private key
	var pubRSA userlib.PKEEncKey
	var priRSA userlib.PKEDecKey
	pubRSA, priRSA, _ = userlib.PKEKeyGen()
	userdata.PrivateKey = priRSA
	// storing the public key in KeyStore
	userlib.KeystoreSet(username+"RSA", pubRSA)

	// generate sign + verify signature key, assign sign key
	var priSign userlib.DSSignKey
	var pubSign userlib.DSVerifyKey
	priSign, pubSign, _ = userlib.DSKeyGen()
	userdata.PrivateSignKey = priSign
	// storing the verify key in Keystore
	userlib.KeystoreSet(username+"Sign", pubSign)

	// Initialize maps and assign them to the user struct
	userdata.FileEncrypt = make(map[uuid.UUID][]byte)
	userdata.FileHMAC = make(map[uuid.UUID][]byte)
	userdata.OwnedFiles = make(map[string]uuid.UUID)
	userdata.InvitedFiles = make(map[string]uuid.UUID)

	//TODO MAYBE CHANGE HOW WE DEAL WITH SALTS????????
	salt := userlib.Hash([]byte(username))
	//Maybe change to something else to store the salt (maybe instide user struct or datastore)
	userByte := userlib.Argon2Key([]byte(username+password), salt, 16)
	userUUID, err := uuid.FromBytes(userByte)
	if err != nil {
		return nil, errors.New("An error occurred while generating a UUID: " + err.Error())
	}

	//userdataByte is the User struct turned into a byte for storage
	userdataByte, err := json.Marshal(userdata)
	//Error message
	if err != nil {
		return nil, errors.New("An error occurred while converting User struct to []bytes: " + err.Error())
	}

	//TODO: Encrypt User Struct
	IV := userlib.RandomBytes(16)
	encryptKey, err := userlib.HashKDF(userByte, []byte("Encrypt"))
	if err != nil {
		return nil, err
	}
	userdataByteEnc := userlib.SymEnc(encryptKey[0:16], IV, userdataByte)

	userlib.DatastoreSet(userUUID, userdataByteEnc)

	// use the HASHKDF alonside the term "HMAC" to generate our HMAC key
	largeHash, err := userlib.HashKDF(userByte, []byte("HMAC"))
	if err != nil {
		return nil, err
	}
	//Calculate the HMAC of the User struct byte string
	HMACValue, err := userlib.HMACEval(largeHash[0:16], userdataByteEnc)
	if err != nil {
		return nil, err
	}

	// generate UUID with hashed username + HMAC

	// COMMENTED OUT AREA
	// userHMAC := userlib.Hash([]byte(largeHash[16:32]))
	HMACUUID, err := uuid.FromBytes(largeHash[16:32])
	// Store the HMAC'd user struct on dataStore
	userlib.DatastoreSet(HMACUUID, HMACValue)

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {

	//TODO MAYBE CHANGE HOW WE DEAL WITH SALTS????????
	salt := userlib.Hash([]byte(username))
	//Maybe change to something else to store the salt (maybe instide user struct or datastore)
	userByte := userlib.Argon2Key([]byte(username+password), salt, 16)
	userUUID, err := uuid.FromBytes(userByte)
	if err != nil {
		return nil, errors.New("An error occurred while generating a UUID: " + err.Error())
	}

	userdataByteEnc, exists := userlib.DatastoreGet(userUUID)

	if exists == false {
		return nil, errors.New("The username and passowrd combination is incorrect")
	}

	// use the HASHKDF alonside the term "HMAC" to generate our HMAC key
	largeHash, err := userlib.HashKDF(userByte, []byte("HMAC"))
	if err != nil {
		return nil, err
	}
	//Calculate the HMAC of the User struct byte string
	HMACValue, err := userlib.HMACEval(largeHash[0:16], userdataByteEnc)
	if err != nil {
		return nil, err
	}

	// generate UUID with hashed username + HMAC

	// COMMENTED OUT AREA
	// userHMAC := userlib.Hash([]byte(largeHash[16:32]))
	HMACUUID, err := uuid.FromBytes(largeHash[16:32])

	dataStoreHMACValue, exists := userlib.DatastoreGet(HMACUUID)
	if exists == false {
		return nil, errors.New("HMAC does not exist in datastore")
	}

	HMACEqual := userlib.HMACEqual(HMACValue, dataStoreHMACValue)
	if HMACEqual != true {
		return nil, errors.New("The user struct or stored HMAC has been tampered with ABORT")
	}

	encryptKey, err := userlib.HashKDF(userByte, []byte("Encrypt"))
	if err != nil {
		return nil, err
	}

	userdataByteDecrypt := userlib.SymDec(encryptKey[0:16], userdataByteEnc)

	var userdata User
	userdataptr = &userdata
	err = json.Unmarshal(userdataByteDecrypt, userdataptr)
	if err != nil {
		return nil, err
	}

	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// FIRST GET USER
	updatedUser, err := GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}
	userdata = updatedUser
	//

	contentTotalLength := len(content)
	fileStructNumber := 0

	// Slice length is the max size of bytes in each file struct
	slicelength := 256

	// For loop to create all the File blocks
	for i := 0; i < contentTotalLength; i += slicelength {
		fileStructNumber += 1
	}
	if fileStructNumber == 0 {
		fileStructNumber += 1
	}

	//
	//
	//
	//
	if userdata.OwnedFiles[filename] != uuid.Nil || userdata.InvitedFiles[filename] != uuid.Nil {
		var fileEncryptKey []byte
		var fileHMACKey []byte
		var fileheadUUID uuid.UUID
		var fileHMACSalt []byte

		//User owns the file
		if userdata.OwnedFiles[filename] != uuid.Nil {
			fileIntermediateUUID := userdata.OwnedFiles[filename]
			fileIntermediateEncKey := userdata.FileEncrypt[fileIntermediateUUID]
			fileIntermediateHMACKey := userdata.FileHMAC[fileIntermediateUUID]

			fileIntermediateEncrypted, ok := userlib.DatastoreGet(fileIntermediateUUID)
			if ok == false {
				return errors.New("datastore couldnt find fileIntermediate")
			}

			fileIntermediateHMACEval, err := userlib.HMACEval(fileIntermediateHMACKey, fileIntermediateEncrypted)
			if err != nil {
				return err
			}

			fileIntermediateHMACUUIDTemp := userlib.Argon2Key([]byte(userdata.Password+filename), userlib.Hash(fileIntermediateHMACKey), 16)
			fileIntermediateHMACUUID, err := uuid.FromBytes(fileIntermediateHMACUUIDTemp)
			if err != nil {
				return err
			}

			actualFileIntermediateHMACEval, ok := userlib.DatastoreGet(fileIntermediateHMACUUID)
			if ok == false {
				return errors.New("datastore couldnt find HMAC")
			}

			HMACEqual := userlib.HMACEqual(fileIntermediateHMACEval, actualFileIntermediateHMACEval)
			if !HMACEqual {
				return errors.New("HMACVALUES NOT EQUAL TO STORED HMAC EVAL VALUE")
			}

			fileIntermediateDec := userlib.SymDec(fileIntermediateEncKey, fileIntermediateEncrypted)

			var fileIntermediateStruct FileIntermediate
			fileIntermptr := &fileIntermediateStruct
			json.Unmarshal(fileIntermediateDec, fileIntermptr)

			fileEncryptKey = fileIntermediateStruct.FileEncrypt
			fileHMACKey = fileIntermediateStruct.FileMac
			fileHMACSalt = fileIntermediateStruct.HMACUUIDSalt
			fileheadUUID = fileIntermediateStruct.FileUUID

			//User was invited to the file
			//TODO: MAYBE CHANGE
		} else {
			fileIntermediateUUID := userdata.InvitedFiles[filename]
			fileIntermediateEncKey := userdata.FileEncrypt[fileIntermediateUUID]
			fileIntermediateHMACKey := userdata.FileHMAC[fileIntermediateUUID]

			fileIntermediateEncrypted, ok := userlib.DatastoreGet(fileIntermediateUUID)
			if ok == false {
				return errors.New("datastore couldnt find invitationIntermediate")
			}

			fileIntermediateHMACEval, err := userlib.HMACEval(fileIntermediateHMACKey, fileIntermediateEncrypted)
			if err != nil {
				return err
			}

			fileIntermediateHMACUUID := userdata.InvitedFiles[filename+"HMACUUID"]

			actualFileIntermediateHMACEval, ok := userlib.DatastoreGet(fileIntermediateHMACUUID)
			if ok == false {
				return errors.New("datastore couldnt find HMAC")
			}

			HMACEqual := userlib.HMACEqual(fileIntermediateHMACEval, actualFileIntermediateHMACEval)
			if !HMACEqual {
				return errors.New("HMACVALUES NOT EQUAL TO STORED HMAC EVAL VALUE")
			}

			fileIntermediateDec := userlib.SymDec(fileIntermediateEncKey, fileIntermediateEncrypted)

			var invitationIntermediateStruct InvitationIntermediate
			fileIntermptr := &invitationIntermediateStruct
			json.Unmarshal(fileIntermediateDec, fileIntermptr)

			fileEncryptKey = invitationIntermediateStruct.FileEncryptKey
			fileHMACKey = invitationIntermediateStruct.FileMACKey
			fileHMACSalt = invitationIntermediateStruct.HMACUUIDSalt
			fileheadUUID = invitationIntermediateStruct.FileHeadUUID

		}
		// File head
		var fileHead File
		fileHeadptr := &fileHead

		//Get the fileHeadEnc from datastore
		fileHeadEnc, ok := userlib.DatastoreGet(fileheadUUID)
		if ok == false {
			return errors.New("datastore couldnt find headFile")
		}

		//Decrypt the head file structure first
		//Put the resultant in fileHead
		err = json.Unmarshal(userlib.SymDec(fileEncryptKey, fileHeadEnc), fileHeadptr)
		if err != nil {
			return err
		}

		//Generates files and stores them
		err = FileGeneratorHelper(fileStructNumber, content, slicelength, fileEncryptKey, fileHMACKey, fileHMACSalt, fileheadUUID)
		if err != nil {
			return err
		}

		//
		return
	}

	//
	//
	//
	//
	// Initialize a Intermediate file structure
	var fileIntermediate FileIntermediate
	fileIntermediate.UserInvitations = make(map[string]uuid.UUID)
	fileIntermediate.KeysIntermediateEncrypt = make(map[string][]byte)
	fileIntermediate.KeysIntermediateHMAC = make(map[string][]byte)

	// uuid, mackey, encrypt key

	// Generates Argon2Key
	// TODO change generation of Argon2Key maybe
	sourceKey := userlib.Argon2Key([]byte(filename+userdata.Password), userlib.Hash([]byte(userdata.Username)), 16)

	// Generate ENC and MAC Keys
	encKey, err := userlib.HashKDF(sourceKey, []byte("Encrypt"))
	if err != nil {
		return err
	}
	macKey, err := userlib.HashKDF(sourceKey, []byte("HMAC"))
	if err != nil {
		return err
	}

	// Store Enc and Hmac Keys
	fileIntermediate.FileEncrypt = encKey[0:16]
	fileIntermediate.FileMac = macKey[0:16]

	// Create random byte array for salt and store that
	fileIntermediate.HMACUUIDSalt = userlib.RandomBytes(32)

	// TODO: store File Enc, Mac, File UUID in intermediate struct

	// Initialize array to store all current file structures
	var fileArray []File = make([]File, int(fileStructNumber))
	// Intialize array to store all current uuids for each file
	var uuidArray []uuid.UUID = make([]uuid.UUID, int(fileStructNumber))

	// The file already exists

	// First generates UUIDS
	for i := 0; i < fileStructNumber; i += 1 {
		// Generates random UUID for file
		randomFileUUID := uuid.New()
		uuidArray[i] = randomFileUUID
	}

	// Next Generate File Blocks
	for i := 0; i < fileStructNumber; i += 1 {
		var currContent []byte
		if i == fileStructNumber-1 {
			currContent = content[i*slicelength : contentTotalLength]
		} else {
			currContent = content[i*slicelength : (i*slicelength + slicelength)]
		}
		// Generates File struct and stores data in it
		var newFileBlock File
		newFileBlock.Content = currContent

		// Places File struct and UUID in respective place
		fileArray[i] = newFileBlock

		if i != fileStructNumber-1 {
			fileArray[i].NextFile = uuidArray[i+1]
		}

		if i == fileStructNumber-1 && i != 0 {
			fileArray[0].LastFile = uuidArray[i]
		}
	}

	// Iterate through FileBlocks, and Encrypt and HMAC them
	for i := 0; i < fileStructNumber; i += 1 {

		//filedataByte is the File struct turned into a byte for storage
		filedataByte, err := json.Marshal(fileArray[i])
		//Error message
		if err != nil {
			return err
		}
		IV := userlib.RandomBytes(16)
		filedataByteEnc := userlib.SymEnc(fileIntermediate.FileEncrypt, IV, filedataByte)

		userlib.DatastoreSet(uuidArray[i], filedataByteEnc)

		//Calculate the HMAC of the File struct byte string
		HMACValue, err := userlib.HMACEval(fileIntermediate.FileMac, filedataByteEnc)
		if err != nil {
			return err
		}

		// Generate a HMAC UUID
		UUIDValue, err := json.Marshal(uuidArray[i])
		if err != nil {
			return err
		}

		generatedHMACUUID := userlib.Argon2Key(UUIDValue, userlib.Hash(fileIntermediate.HMACUUIDSalt), 16)

		HMACUUID, err := uuid.FromBytes(generatedHMACUUID)
		if err != nil {
			return err
		}

		// Store the HMAC'd user struct on dataStore
		userlib.DatastoreSet(HMACUUID, HMACValue)

	}

	// Store the head file uuid
	fileIntermediate.FileUUID = uuidArray[0]

	// Generate UUID for fileIntermedaite
	fileIntermediateUUID := uuid.New()
	// Generate Enc and HMAC key for fileIntermediate
	fileIntermediateEncKey := userlib.RandomBytes(16)

	fileIntermediateHMACKey := userlib.RandomBytes(16)

	fileIntermediateHMACUUIDTemp := userlib.Argon2Key([]byte(userdata.Password+filename), userlib.Hash(fileIntermediateHMACKey), 16)
	fileIntermediateHMACUUID, err := uuid.FromBytes(fileIntermediateHMACUUIDTemp)
	if err != nil {
		return err
	}
	marshalStructContent, err := json.Marshal(fileIntermediate)
	err = EncryptHMACHelper(fileIntermediateEncKey, fileIntermediateHMACKey, marshalStructContent,
		fileIntermediateUUID, fileIntermediateHMACUUID)
	if err != nil {
		return err
	}

	// Store fileIntermediateUUID in userdata user struct
	userdata.OwnedFiles[filename] = fileIntermediateUUID
	// Store fileHMAC
	userdata.FileEncrypt[fileIntermediateUUID] = fileIntermediateEncKey
	userdata.FileHMAC[fileIntermediateUUID] = fileIntermediateHMACKey
	// Store fileEncKey

	// randomly generate the UUID for all file structures
	// HMAC
	// Store the data in the file structure (We will need to break the data into small chunks of some length)
	// We need to encrpyt the file stucture
	// We need to HMAC the file structure

	// We then create a HMAC and encrypt key for the file intermediate structure
	// WE need to encrypt and HMAC the file intermediate structure
	// We need to store that in the Userfile
	// We need to encrypt and reHMAC the Userfile
	// If the file already existed and we are just overwriting it
	// duplicates for usr structure

	//TODO MAYBE CHANGE HOW WE DEAL WITH SALTS????????
	salt := userlib.Hash([]byte(userdata.Username))
	userSourceKey := userlib.Argon2Key([]byte(userdata.Username+userdata.Password), salt, 16)
	// MAYBE WE NEED TO UNPOINTER THE POINTER TODO MAYBE
	userByte, err := json.Marshal(userdata)
	if err != nil {
		return err
	}

	userHMAC, userEnc, uuidHMAC, err := EncryptHMACHelperSource(userSourceKey, userByte)
	if err != nil {
		return err
	}

	newUserUUID, err := uuid.FromBytes(userSourceKey)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(newUserUUID, userEnc)

	userlib.DatastoreSet(uuidHMAC, userHMAC)

	// TODO deal with intermediates
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {

	// FIRST GET USER
	updatedUser, err := GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}
	userdata = updatedUser
	//

	// Total length of bytes
	contentTotalLength := len(content)
	fileStructNumber := 0

	// Slice length is the max size of bytes in each file struct
	slicelength := 256

	// For loop to create all the File blocks
	for i := 0; i < contentTotalLength; i += slicelength {
		fileStructNumber += 1
	}
	if fileStructNumber == 0 {
		fileStructNumber += 1
	}

	//Make new file and UUID arrays
	var fileArray []File = make([]File, int(fileStructNumber))
	var uuidArray []uuid.UUID = make([]uuid.UUID, int(fileStructNumber))

	// Generate UUIDS
	for i := 0; i < fileStructNumber; i += 1 {
		// Generates random UUID for file
		randomFileUUID := uuid.New()
		uuidArray[i] = randomFileUUID
	}

	// Generate File Blocks
	for i := 0; i < fileStructNumber; i += 1 {
		var currContent []byte
		if i == fileStructNumber-1 {
			currContent = content[i*slicelength : contentTotalLength]
		} else {
			currContent = content[i*slicelength : (i*slicelength + slicelength)]
		}
		// Generates File struct and stores data in it
		var newFileBlock File
		newFileBlock.Content = currContent

		// Places File struct and UUID in respective place
		fileArray[i] = newFileBlock

		if i != fileStructNumber-1 {
			fileArray[i].NextFile = uuidArray[i+1]
		}

	}

	// Get HEAD file and Encryption and HMAC keys + salts
	fileEncryptKey, fileHMACKey, fileHeadUUID, fileHMACSalt, fileHead, err := userdata.GetHeadFile(filename)
	print(len(fileHMACKey), "This is HMAC")
	if err != nil {
		return err
	}

	// Iterate through FileBlocks, and Encrypt and HMAC them
	for i := 0; i < fileStructNumber; i += 1 {

		//filedataByte is the File struct turned into a byte for storage
		filedataByte, err := json.Marshal(fileArray[i])
		//Error message

		if err != nil {
			return err
		}
		IV := userlib.RandomBytes(16)
		filedataByteEnc := userlib.SymEnc(fileEncryptKey, IV, filedataByte)

		userlib.DatastoreSet(uuidArray[i], filedataByteEnc)

		//Calculate the HMAC of the File struct byte string
		HMACValue, err := userlib.HMACEval(fileHMACKey, filedataByteEnc)
		if err != nil {
			return err
		}

		// Generate a HMAC UUID
		UUIDValue, err := json.Marshal(uuidArray[i])
		if err != nil {
			return err
		}

		generatedHMACUUID := userlib.Argon2Key(UUIDValue, userlib.Hash(fileHMACSalt), 16)

		HMACUUID, err := uuid.FromBytes(generatedHMACUUID)
		if err != nil {
			return err
		}

		// Store the HMAC'd struct on dataStore
		userlib.DatastoreSet(HMACUUID, HMACValue)
	}

	// 2 Cases, The is currently one file blocked stored, and there is more than one file block stored
	// Only one file block is stored:
	if fileHead.NextFile == uuid.Nil {
		fileHead.NextFile = uuidArray[0]
		fileHead.LastFile = uuidArray[fileStructNumber-1]
		// More than one file block is currently stored before append
	} else {
		//Gets the last file
		lastFileUUID := fileHead.LastFile
		lastFile, lastFileHMACUUID, err := DecryptHMACHelper(fileEncryptKey, fileHMACKey, lastFileUUID, fileHMACSalt)
		if err != nil {
			return err
		}

		lastFile.NextFile = uuidArray[0]
		fileHead.LastFile = uuidArray[fileStructNumber-1]

		lastFileBytes, err := json.Marshal(lastFile)
		if err != nil {
			return err
		}

		err = EncryptHMACHelper(fileEncryptKey, fileHMACKey, lastFileBytes, lastFileUUID, lastFileHMACUUID)
		if err != nil {
			return err
		}
	}

	fileHeadBytes, err := json.Marshal(fileHead)
	if err != nil {
		return err
	}
	fileHeadUUIDBytes, err := json.Marshal(fileHeadUUID)
	if err != nil {
		return err
	}
	fileHeadHMACUUIDTemp := userlib.Argon2Key(fileHeadUUIDBytes, userlib.Hash(fileHMACSalt), 16)
	fileHeadHMACUUID, err := uuid.FromBytes(fileHeadHMACUUIDTemp)
	if err != nil {
		return err
	}
	err = EncryptHMACHelper(fileEncryptKey, fileHMACKey, fileHeadBytes, fileHeadUUID, fileHeadHMACUUID)
	if err != nil {
		return err
	}

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	/* 	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	   	if err != nil {
	   		return nil, err
	   	}
	   	dataJSON, ok := userlib.DatastoreGet(storageKey)
	   	if !ok {
	   		return nil, errors.New(strings.ToTitle("file not found"))
	   	}
	   	err = json.Unmarshal(dataJSON, &content) */

	// 2 cases, owner of file and invited to file
	// retrieve file
	//owner case
	//	Get intermediate uuid,

	// FIRST GET USER
	updatedUser, err := GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return nil, err
	}
	userdata = updatedUser
	//

	if userdata.OwnedFiles[filename] == uuid.Nil && userdata.InvitedFiles[filename] == uuid.Nil {
		return nil, errors.New("given filename dne in personal namespace of the caller")
	}

	var fileEncryptKey []byte
	var fileHMACKey []byte
	var fileheadUUID uuid.UUID
	var fileHMACSalt []byte

	if userdata.OwnedFiles[filename] != uuid.Nil {
		fileIntermediateUUID := userdata.OwnedFiles[filename]
		fileIntermediateEncKey := userdata.FileEncrypt[fileIntermediateUUID]
		fileIntermediateHMACKey := userdata.FileHMAC[fileIntermediateUUID]

		fileIntermediateEncrypted, ok := userlib.DatastoreGet(fileIntermediateUUID)
		if ok == false {
			return nil, errors.New("datastore couldnt find fileIntermediate")
		}

		fileIntermediateHMACEval, err := userlib.HMACEval(fileIntermediateHMACKey, fileIntermediateEncrypted)
		if err != nil {
			return nil, err
		}

		fileIntermediateHMACUUIDTemp := userlib.Argon2Key([]byte(userdata.Password+filename), userlib.Hash(fileIntermediateHMACKey), 16)
		fileIntermediateHMACUUID, err := uuid.FromBytes(fileIntermediateHMACUUIDTemp)
		if err != nil {
			return nil, err
		}

		actualFileIntermediateHMACEval, ok := userlib.DatastoreGet(fileIntermediateHMACUUID)
		if ok == false {
			return nil, errors.New("datastore couldnt find HMAC")
		}

		HMACEqual := userlib.HMACEqual(fileIntermediateHMACEval, actualFileIntermediateHMACEval)
		if !HMACEqual {
			return nil, errors.New("HMACVALUES NOT EQUAL TO STORED HMAC EVAL VALUE")
		}

		fileIntermediateDec := userlib.SymDec(fileIntermediateEncKey, fileIntermediateEncrypted)

		var fileIntermediateStruct FileIntermediate
		fileIntermptr := &fileIntermediateStruct
		json.Unmarshal(fileIntermediateDec, fileIntermptr)

		fileEncryptKey = fileIntermediateStruct.FileEncrypt
		fileHMACKey = fileIntermediateStruct.FileMac
		fileHMACSalt = fileIntermediateStruct.HMACUUIDSalt
		fileheadUUID = fileIntermediateStruct.FileUUID

	} else {
		fileIntermediateUUID := userdata.InvitedFiles[filename]
		fileIntermediateEncKey := userdata.FileEncrypt[fileIntermediateUUID]
		fileIntermediateHMACKey := userdata.FileHMAC[fileIntermediateUUID]

		fileIntermediateEncrypted, ok := userlib.DatastoreGet(fileIntermediateUUID)
		if ok == false {
			return nil, errors.New("datastore couldnt find invitationIntermediate")
		}

		fileIntermediateHMACEval, err := userlib.HMACEval(fileIntermediateHMACKey, fileIntermediateEncrypted)
		if err != nil {
			return nil, err
		}

		fileIntermediateHMACUUID := userdata.InvitedFiles[filename+"HMACUUID"]

		actualFileIntermediateHMACEval, ok := userlib.DatastoreGet(fileIntermediateHMACUUID)
		if ok == false {
			return nil, errors.New("datastore couldnt find HMAC")
		}

		HMACEqual := userlib.HMACEqual(fileIntermediateHMACEval, actualFileIntermediateHMACEval)
		if !HMACEqual {
			return nil, errors.New("HMACVALUES NOT EQUAL TO STORED HMAC EVAL VALUE")
		}

		fileIntermediateDec := userlib.SymDec(fileIntermediateEncKey, fileIntermediateEncrypted)

		var invitationIntermediateStruct InvitationIntermediate
		fileIntermptr := &invitationIntermediateStruct
		json.Unmarshal(fileIntermediateDec, fileIntermptr)

		fileEncryptKey = invitationIntermediateStruct.FileEncryptKey
		fileHMACKey = invitationIntermediateStruct.FileMACKey
		fileHMACSalt = invitationIntermediateStruct.HMACUUIDSalt
		fileheadUUID = invitationIntermediateStruct.FileHeadUUID

	}

	// File head
	var fileHead File
	fileHeadptr := &fileHead

	//Get the fileHeadEnc from datastore
	fileHeadEnc, ok := userlib.DatastoreGet(fileheadUUID)
	if ok == false {
		return nil, errors.New("datastore couldnt find headFile")
	}

	//HMAC it
	fileHeadHMAC, err := userlib.HMACEval(fileHMACKey, fileHeadEnc)
	if err != nil {
		return nil, err
	}

	// Generate a HMAC UUID
	UUIDValue, err := json.Marshal(fileheadUUID)
	if err != nil {
		return nil, err
	}

	//HMACUUIDc finder
	generatedHMACUUID := userlib.Argon2Key(UUIDValue, userlib.Hash(fileHMACSalt), 16)

	HMACUUID, err := uuid.FromBytes(generatedHMACUUID)
	if err != nil {
		return nil, err
	}

	HMACActualEval, ok := userlib.DatastoreGet(HMACUUID)

	if ok == false {
		return nil, errors.New("datastore couldnt find headFile")
	}

	equal := userlib.HMACEqual(fileHeadHMAC, HMACActualEval)
	if !equal {
		return nil, errors.New("fileHead HMACVALUE NOT EQUAL TO STORED HMAC EVAL VALUE")
	}

	//Decrypt the head file structure first
	//Put the resultant in fileHead
	err = json.Unmarshal(userlib.SymDec(fileEncryptKey, fileHeadEnc), fileHeadptr)
	if err != nil {
		return nil, err
	}

	totalContent := fileHead.Content
	nextPointer := fileHead.NextFile

	/* var fileEncryptKey []byte
	var fileHMACKey []byte
	var fileheadUUID uuid.UUID
	var fileHMACSalt []byte */

	for nextPointer != uuid.Nil {
		fileBlockEnc, ok := userlib.DatastoreGet(nextPointer)
		if ok == false {
			return nil, errors.New("datastore couldnt find fileBlock")
		}

		// Generate a HMAC UUID
		UUIDValue, err := json.Marshal(nextPointer)
		if err != nil {
			return nil, err
		}

		//HMACUUIDc finder
		generatedHMACUUID := userlib.Argon2Key(UUIDValue, userlib.Hash(fileHMACSalt), 16)
		HMACUUID, err := uuid.FromBytes(generatedHMACUUID)
		if err != nil {
			return nil, err
		}

		HMACEvaluated, err := userlib.HMACEval(fileHMACKey, fileBlockEnc)
		if err != nil {
			return nil, err
		}

		HMACReal, ok := userlib.DatastoreGet(HMACUUID)
		if ok == false {
			return nil, errors.New("datastore couldnt find fileBlock")
		}

		equal = userlib.HMACEqual(HMACEvaluated, HMACReal)

		if !equal {
			return nil, errors.New("HMAC not equal")
		}

		var fileStruct File
		err = json.Unmarshal(userlib.SymDec(fileEncryptKey, fileBlockEnc), &fileStruct)
		if err != nil {
			return nil, err
		}

		nextPointer = fileStruct.NextFile
		totalContent = append(totalContent, fileStruct.Content...)
	}

	return totalContent, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	// FIRST GET USER
	updatedUser, err := GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return uuid.Nil, err
	}
	userdata = updatedUser
	//

	//Checks if filename exists in userspace
	if userdata.InvitedFiles[filename] == uuid.Nil && userdata.OwnedFiles[filename] == uuid.Nil {
		return uuid.Nil, errors.New("Filename does not exist in user filespace")
	}

	//Gets the recipient RSA for later
	recipientRSA, ok := userlib.KeystoreGet(recipientUsername + "RSA")
	if !ok {
		return uuid.Nil, errors.New("Recipient User doesn't exist")
	}

	//Gets private sign key
	privateSign := userdata.PrivateSignKey

	//Initialize Invitation file
	var newInvitation Invitation

	//1st case, owner owns the file
	if userdata.OwnedFiles[filename] != uuid.Nil {
		currIntermediateFile, err := userdata.GetIntermediateFile(filename)
		if err != nil {
			return uuid.Nil, err
		}

		var newInvitationIntermediate InvitationIntermediate

		currFileEncryptKey := currIntermediateFile.FileEncrypt
		currFileMacKey := currIntermediateFile.FileMac
		currFileUUID := currIntermediateFile.FileUUID
		currHMACUUIDSalt := currIntermediateFile.HMACUUIDSalt

		newInvitationIntermediate.FileEncryptKey = currFileEncryptKey
		newInvitationIntermediate.FileHeadUUID = currFileUUID
		newInvitationIntermediate.FileMACKey = currFileMacKey
		newInvitationIntermediate.HMACUUIDSalt = currHMACUUIDSalt

		// Generates keys and UUID values from userdata.password and filename
		tempByte := userlib.Argon2Key([]byte(userdata.Password+filename), userlib.Hash([]byte(recipientUsername)), 16)
		tempInvIntUUID, err := userlib.HashKDF(tempByte, []byte("UUID"))
		if err != nil {
			return uuid.Nil, err
		}
		tempInvIntHMACUUID, err := userlib.HashKDF(tempByte, []byte("HMACUUID"))
		if err != nil {
			return uuid.Nil, err
		}
		tempInvIntEncKey, err := userlib.HashKDF(tempByte, []byte("EncKey"))
		if err != nil {
			return uuid.Nil, err
		}
		tempInvIntHMACKey, err := userlib.HashKDF(tempByte, []byte("HMACKey"))
		if err != nil {
			return uuid.Nil, err
		}

		// Generated Values
		newInvitationIntermediateUUID, err := uuid.FromBytes(tempInvIntUUID[0:16])
		if err != nil {
			return uuid.Nil, err
		}

		newInvitationIntermediateHMACUUID, err := uuid.FromBytes(tempInvIntHMACUUID[0:16])
		if err != nil {
			return uuid.Nil, err
		}

		marshaledInvIntUUID, err := json.Marshal(newInvitationIntermediateUUID)
		if err != nil {
			return uuid.Nil, err
		}
		marshaledInvIntHMACUUID, err := json.Marshal(newInvitationIntermediateHMACUUID)
		if err != nil {
			return uuid.Nil, err
		}

		// Add values to invitation file
		newInvIntUUIDRSA, err := userlib.PKEEnc(recipientRSA, marshaledInvIntUUID)
		if err != nil {
			return uuid.Nil, err
		}
		newInvitationIntermediateHMACUUIDRSA, err := userlib.PKEEnc(recipientRSA, marshaledInvIntHMACUUID)
		if err != nil {
			return uuid.Nil, err
		}
		newInvitationIntermediateEncKeyRSA, err := userlib.PKEEnc(recipientRSA, tempInvIntEncKey[0:16])
		if err != nil {
			return uuid.Nil, err
		}
		newInvitationIntermediateHMACKeyRSA, err := userlib.PKEEnc(recipientRSA, tempInvIntHMACKey[0:16])
		if err != nil {
			return uuid.Nil, err
		}

		//UUIDs for encrypting later
		invIntHMACUUID, err := uuid.FromBytes(tempInvIntHMACUUID[0:16])
		invIntUUID, err := uuid.FromBytes(tempInvIntUUID[0:16])

		//Putting all necessary files in invitation
		newInvitation.EncIntermediateUUID = newInvIntUUIDRSA
		newInvitation.RSAEncryptKey = newInvitationIntermediateEncKeyRSA
		newInvitation.RSAMacKey = newInvitationIntermediateHMACKeyRSA
		newInvitation.RSAMacUUID = newInvitationIntermediateHMACUUIDRSA
		signedMessage, err := userlib.DSSign(privateSign, []byte(userdata.Username))
		if err != nil {
			return uuid.Nil, err
		}
		newInvitation.Signature = signedMessage

		//Encrypt and HMAC the invitation intermediate
		newInvitationIntermediateBytes, err := json.Marshal(newInvitationIntermediate)
		if err != nil {
			return uuid.Nil, err
		}
		EncryptHMACHelper(tempInvIntEncKey[0:16], tempInvIntHMACKey[0:16], newInvitationIntermediateBytes, invIntUUID, invIntHMACUUID)

		//Now we need to add values to fileIntermediate
		currIntermediateFile.UserInvitations[recipientUsername] = newInvitationIntermediateUUID
		currIntermediateFile.KeysIntermediateEncrypt[recipientUsername] = tempInvIntEncKey[0:16]
		currIntermediateFile.KeysIntermediateHMAC[recipientUsername] = tempInvIntHMACKey[0:16]

		currIntermediateFileUUID := userdata.OwnedFiles[filename]
		currIntermediateFileMacKey := userdata.FileHMAC[currIntermediateFileUUID]
		currIntermediateFileEncKey := userdata.FileEncrypt[currIntermediateFileUUID]

		fileIntermediateHMACUUIDTemp := userlib.Argon2Key([]byte(userdata.Password+filename), userlib.Hash(currIntermediateFileMacKey), 16)
		currIntermediateFileHMACUUID, err := uuid.FromBytes(fileIntermediateHMACUUIDTemp)
		if err != nil {
			return uuid.Nil, err
		}

		currIntermediateFileBytes, err := json.Marshal(currIntermediateFile)
		if err != nil {
			return uuid.Nil, err
		}

		err = EncryptHMACHelper(currIntermediateFileEncKey, currIntermediateFileMacKey, currIntermediateFileBytes, currIntermediateFileUUID, currIntermediateFileHMACUUID)
		if err != nil {
			return uuid.Nil, err
		}

		// Case 2 if not file owner
		// TODO
	} else {
		//Get the invitation intermediate items

		_, err := updatedUser.GetInvitationIntermediate(filename)

		if err != nil {
			return uuid.Nil, err
		}
		currInvitationIntermediateUUID := userdata.InvitedFiles[filename]
		currInvitationIntermediateEncKey := userdata.FileEncrypt[currInvitationIntermediateUUID]
		currInvitationIntermediateMacKey := userdata.FileHMAC[currInvitationIntermediateUUID]
		currInvitationIntermediateHMACUUID := userdata.InvitedFiles[filename+"HMACUUID"]

		currInvitationIntermediateUUIDByte, err := json.Marshal(currInvitationIntermediateUUID)
		if err != nil {
			return uuid.Nil, err
		}
		currInvitationIntermediateHMACUUIDByte, err := json.Marshal(currInvitationIntermediateHMACUUID)
		if err != nil {
			return uuid.Nil, err
		}

		//public RSA and private sign
		userSign := userdata.PrivateSignKey
		recipientRSA, ok := userlib.KeystoreGet(recipientUsername + "RSA")
		if !ok {
			return uuid.Nil, errors.New("The Recipientusername RSA doesnt exist (odd problem take closer look)")
		}

		invIntEncKeyRSA, err := userlib.PKEEnc(recipientRSA, currInvitationIntermediateEncKey)
		if err != nil {
			return uuid.Nil, err
		}
		invIntMacKeyRSA, err := userlib.PKEEnc(recipientRSA, currInvitationIntermediateMacKey)
		if err != nil {
			return uuid.Nil, err
		}
		invIntUUIDRSA, err := userlib.PKEEnc(recipientRSA, currInvitationIntermediateUUIDByte)
		if err != nil {
			return uuid.Nil, err
		}
		invIntHMACUUIDRSA, err := userlib.PKEEnc(recipientRSA, currInvitationIntermediateHMACUUIDByte)
		if err != nil {
			return uuid.Nil, err
		}

		signedKey, err := userlib.DSSign(userSign, []byte(userdata.Username))
		if err != nil {
			return uuid.Nil, err
		}

		newInvitation.EncIntermediateUUID = invIntUUIDRSA
		newInvitation.RSAEncryptKey = invIntEncKeyRSA
		newInvitation.RSAMacKey = invIntMacKeyRSA
		newInvitation.RSAMacUUID = invIntHMACUUIDRSA
		newInvitation.Signature = signedKey

	}
	//Store the invitation inside the datastore

	invitationUUID := uuid.New()
	newInvitationBytes, err := json.Marshal(newInvitation)
	if err != nil {
		return uuid.Nil, err
	}
	userlib.DatastoreSet(invitationUUID, newInvitationBytes)

	return invitationUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// FIRST GET USER
	updatedUser, err := GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}
	userdata = updatedUser
	//
	//Get invitation from invitationPtr
	invitationBytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("invitation doesn't exist")
	}
	//Checks if filename is already found in user storage dicts
	if userdata.OwnedFiles[filename] != uuid.Nil || userdata.InvitedFiles[filename] != uuid.Nil {
		return errors.New("Filename already exists")
	}
	//Need to check if revoked TODO

	var invitation Invitation

	json.Unmarshal(invitationBytes, &invitation)
	// Check the signature
	senderSign, ok := userlib.KeystoreGet(senderUsername + "Sign")
	if !ok {
		return errors.New("sender doesnt exist")
	}
	err = userlib.DSVerify(senderSign, []byte(senderUsername), invitation.Signature)
	if err != nil {
		return err
	}

	// Decrypting the RSA keys
	if !ok {
		return errors.New("User RSA doesnt exist")
	}
	intermediateEncKey, err := userlib.PKEDec(userdata.PrivateKey, invitation.RSAEncryptKey)
	if err != nil {
		return err
	}
	intermediateMacKey, err := userlib.PKEDec(userdata.PrivateKey, invitation.RSAMacKey)
	if err != nil {
		return err
	}
	intermediateUUIDTemp, err := userlib.PKEDec(userdata.PrivateKey, invitation.EncIntermediateUUID)
	if err != nil {
		return err
	}
	intermedaiteHMACUUIDTemp, err := userlib.PKEDec(userdata.PrivateKey, invitation.RSAMacUUID)
	if err != nil {
		return err
	}

	var intermediateUUID uuid.UUID
	var intermediateHMACUUID uuid.UUID

	json.Unmarshal(intermediateUUIDTemp, &intermediateUUID)
	json.Unmarshal(intermedaiteHMACUUIDTemp, &intermediateHMACUUID)

	/* 	intermediateUUID, err := uuid.FromBytes(intermediateUUIDTemp)
	   	intermediateHMACUUID, err := uuid.FromBytes(intermedaiteHMACUUIDTemp) */

	// HMAC and Decrypt the file
	thisInvitationIntermediate, err := DecryptHMACInvInt(intermediateEncKey, intermediateMacKey, intermediateUUID, intermediateHMACUUID)
	if err != nil {
		return err
	}

	//Check if we have access to head of file
	test, ok := userlib.DatastoreGet(thisInvitationIntermediate.FileHeadUUID)
	if !ok {
		return errors.New("Access to file revoked")
	}

	if test == nil {
		return errors.New("Access to file revoked")
	}

	//Add items to userdata

	userdata.InvitedFiles[filename] = intermediateUUID
	userdata.FileEncrypt[intermediateUUID] = intermediateEncKey
	userdata.FileHMAC[intermediateUUID] = intermediateMacKey
	userdata.InvitedFiles[filename+"HMACUUID"] = intermediateHMACUUID

	// Storing userdata in the datastore again
	salt := userlib.Hash([]byte(userdata.Username))
	userSourceKey := userlib.Argon2Key([]byte(userdata.Username+userdata.Password), salt, 16)
	// MAYBE WE NEED TO UNPOINTER THE POINTER TODO MAYBE
	userByte, err := json.Marshal(userdata)
	if err != nil {
		return err
	}

	userHMAC, userEnc, uuidHMAC, err := EncryptHMACHelperSource(userSourceKey, userByte)
	if err != nil {
		return err
	}

	newUserUUID, err := uuid.FromBytes(userSourceKey)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(newUserUUID, userEnc)

	userlib.DatastoreSet(uuidHMAC, userHMAC)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// FIRST GET USER
	updatedUser, err := GetUser(userdata.Username, userdata.Password)
	if err != nil {
		return err
	}
	userdata = updatedUser

	//Obtain the file intermediate
	userintermediateFile, err := updatedUser.GetIntermediateFile(filename)
	if err != nil {
		return err
	}

	//Make sure the user we are trying to revoke from actually exists
	_, ok := userintermediateFile.UserInvitations[recipientUsername]
	if !ok {
		return errors.New("Recipient user does not exist")
	}

	//Iterate through all storefiles and change the uuid for each item
	headFileEncryptKey, headFileHMACKey, headFileUUID, headFileHMACSalt, headFile, err := userdata.GetHeadFile(filename)
	if err != nil {
		return err
	}

	//Delete the Head file UUID and HMACUUID
	userlib.DatastoreDelete(headFileUUID)
	userlib.DatastoreDelete(userintermediateFile.FileUUID)

	previousFile := headFile
	currFileUUID := headFile.NextFile

	// Make sure that the lastfile pointer is Nil in case we only have the head block
	headFile.LastFile = uuid.Nil

	fileBlocks := make([]File, 0)
	fileUUIDS := make([]uuid.UUID, 0)

	/* fileBlocks = append(fileBlocks, headFile) */
	fileUUIDS = append(fileUUIDS, uuid.New())

	for currFileUUID != uuid.Nil {
		//Creates new UUID and set it as the previous file's NextFile
		newFileUUID := uuid.New()
		previousFile.NextFile = newFileUUID

		//Get the current file from currFileUUID
		currFileBlock, currHMACUUID, err := DecryptHMACHelper(headFileEncryptKey, headFileHMACKey, currFileUUID, headFileHMACSalt)
		if err != nil {
			return err
		}

		//Deletes the HMACUUID and currfileUUID
		userlib.DatastoreDelete(currHMACUUID)
		userlib.DatastoreDelete(currFileUUID)

		//Appending the previous file block and the new file uuid
		fileUUIDS = append(fileUUIDS, newFileUUID)
		fileBlocks = append(fileBlocks, previousFile)

		//For Base case
		if currFileBlock.NextFile == uuid.Nil {
			fileBlocks[0].LastFile = currFileUUID
		}

		//Iteration
		currFileUUID = currFileBlock.NextFile
		previousFile = currFileBlock

	}

	fileBlocks = append(fileBlocks, previousFile)

	print(len(fileBlocks))
	print(len(fileUUIDS))

	// We have to reencrypt and remac everything

	// Generate new Enc, HMAC and HMACSalts
	newEncKey := userlib.RandomBytes(16)
	newHMACKey := userlib.RandomBytes(16)
	newHMACSalt := userlib.RandomBytes(32)

	// This means changing the enc and mac keys and also changing the hmacuuidsalt
	totalBlocks := len(fileBlocks)
	for i := 0; i < totalBlocks; i += 1 {
		currFileBlock := fileBlocks[i]
		currUUID := fileUUIDS[i]

		//Turn current Block into []byte
		currFileBlockByte, err := json.Marshal(currFileBlock)
		if err != nil {
			return err
		}

		UUIDValue, err := json.Marshal(currUUID)
		if err != nil {
			return err
		}

		generatedHMACUUID := userlib.Argon2Key(UUIDValue, userlib.Hash(newHMACSalt), 16)
		currHMACUUID, err := uuid.FromBytes(generatedHMACUUID)
		if err != nil {
			return err
		}

		err = EncryptHMACHelper(newEncKey, newHMACKey, currFileBlockByte, currUUID, currHMACUUID)
		if err != nil {
			return err
		}

	}

	//Delete the user from the invitations list
	delete(userintermediateFile.UserInvitations, recipientUsername)
	delete(userintermediateFile.KeysIntermediateEncrypt, recipientUsername)
	delete(userintermediateFile.KeysIntermediateHMAC, recipientUsername)

	//Go through all Invitational intermediates and change accordingly
	keys := make([]string, 0, len(userintermediateFile.UserInvitations))
	for k := range userintermediateFile.UserInvitations {
		keys = append(keys, k)
	}

	for i := 0; i < len(keys); i += 1 {
		currUser := keys[i]
		// Get the user IntInv from keystore
		userIntInv := userintermediateFile.UserInvitations[currUser]
		sharedIntInvByte, ok := userlib.DatastoreGet(userIntInv)
		if !ok {
			return errors.New("Unable to retrive user IntInv from keystore")
		}

		// Generates keys and UUID values from userdata.password and filename
		tempByte := userlib.Argon2Key([]byte(userdata.Password+filename), userlib.Hash([]byte(keys[i])), 16)
		/* tempInvIntUUID, err := userlib.HashKDF(tempByte, []byte("UUID")) */
		if err != nil {
			return err
		}
		tempInvIntHMACUUID, err := userlib.HashKDF(tempByte, []byte("HMACUUID"))
		if err != nil {
			return err
		}
		tempInvIntEncKey, err := userlib.HashKDF(tempByte, []byte("EncKey"))
		if err != nil {
			return err
		}
		tempInvIntHMACKey, err := userlib.HashKDF(tempByte, []byte("HMACKey"))
		if err != nil {
			return err
		}
		//UUIDs for encrypting later
		invIntHMACUUID, err := uuid.FromBytes(tempInvIntHMACUUID[0:16])
		/* invIntUUID, err := uuid.FromBytes(tempInvIntUUID[0:16]) */

		invIntHMACKey := tempInvIntHMACKey[0:16]
		invIntEncKey := tempInvIntEncKey[0:16]

		HMACEvalValue, err := userlib.HMACEval(invIntHMACKey, sharedIntInvByte)
		if err != nil {
			return err
		}

		HMACAcutalValue, ok := userlib.DatastoreGet(invIntHMACUUID)
		if !ok {
			return errors.New("Unable to retrive user IntInvHMAC from keystore")
		}

		equal := userlib.HMACEqual(HMACAcutalValue, HMACEvalValue)
		if !equal {
			return errors.New("HMAC actual not equal to HMAC equal")
		}

		//Decrypt the value
		var sharedInvInt InvitationIntermediate

		sharedInvIntDec := userlib.SymDec(invIntEncKey, sharedIntInvByte)
		err = json.Unmarshal(sharedInvIntDec, &sharedInvInt)
		if err != nil {
			return err
		}

		//Assign new values and reencrypt
		sharedInvInt.FileEncryptKey = newEncKey
		sharedInvInt.FileMACKey = newHMACKey
		sharedInvInt.HMACUUIDSalt = newHMACSalt
		sharedInvInt.FileHeadUUID = fileUUIDS[0]

		sharedInvIntMarshaled, err := json.Marshal(sharedInvInt)
		if err != nil {
			return err
		}

		err = EncryptHMACHelper(invIntEncKey, invIntHMACKey, sharedInvIntMarshaled, userIntInv, invIntHMACUUID)
		if err != nil {
			return err
		}

	}

	//Change User intermediate and encrypt + HMAC it
	userintermediateFile.FileEncrypt = newEncKey
	userintermediateFile.FileMac = newHMACKey
	userintermediateFile.HMACUUIDSalt = newHMACSalt
	userintermediateFile.FileUUID = fileUUIDS[0]

	fileIntermediateUUID := userdata.OwnedFiles[filename]
	fileIntermediateEncKey := userdata.FileEncrypt[fileIntermediateUUID]
	fileIntermediateHMACKey := userdata.FileHMAC[fileIntermediateUUID]

	fileIntermediateHMACUUIDTemp := userlib.Argon2Key([]byte(userdata.Password+filename), userlib.Hash(fileIntermediateHMACKey), 16)
	fileIntermediateHMACUUID, err := uuid.FromBytes(fileIntermediateHMACUUIDTemp)
	if err != nil {
		return err
	}

	userintermediateFileByte, err := json.Marshal(userintermediateFile)
	if err != nil {
		return err
	}

	err = EncryptHMACHelper(fileIntermediateEncKey, fileIntermediateHMACKey, userintermediateFileByte, fileIntermediateUUID, fileIntermediateHMACUUID)
	if err != nil {
		return err
	}

	return nil

}

func EncryptHMACHelperSource(sourcekey []byte, content []byte) ([]byte, []byte, uuid.UUID, error) {

	// Generate ENC and MAC Keys
	encKey, err := userlib.HashKDF(sourcekey, []byte("Encrypt"))
	if err != nil {
		return nil, nil, uuid.New(), err
	}
	macKey, err := userlib.HashKDF(sourcekey, []byte("HMAC"))
	if err != nil {
		return nil, nil, uuid.New(), err
	}

	// Encrypt Struct
	IV := userlib.RandomBytes(16)
	contentEnc := userlib.SymEnc(encKey[0:16], IV, content)

	// Calculate the HMAC of the struct byte string
	HMAC, err := userlib.HMACEval(macKey[0:16], contentEnc)
	if err != nil {
		return nil, nil, uuid.New(), err
	}
	UUID, err := uuid.FromBytes(macKey[16:32])

	return HMAC, contentEnc, UUID, nil
}

func EncryptHMACHelper(encKey []byte, HMACKey []byte, content []byte, contentUUID uuid.UUID, hmacUUID uuid.UUID) error {

	// Encrypt Struct
	IV := userlib.RandomBytes(16)
	contentEnc := userlib.SymEnc(encKey, IV, content)

	// Calculate the HMAC of the struct byte string
	HMAC, err := userlib.HMACEval(HMACKey, contentEnc)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(contentUUID, contentEnc)
	userlib.DatastoreSet(hmacUUID, HMAC)

	return nil
}

// Takes in encKey, HMACKey, fileUUId, and hmacSalt, Returnsthe fileBlock and HMACUUID
func DecryptHMACHelper(encKey []byte, HMACKey []byte, fileUUID uuid.UUID, hmacSalt []byte) (fileBlock File, HMACUUID uuid.UUID, err error) {
	fileEnc, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return File{}, uuid.Nil, errors.New("fileUUID does not point to a file")
	}

	calulatedHMACValue, err := userlib.HMACEval(HMACKey, fileEnc)
	if err != nil {
		return File{}, uuid.Nil, err
	}

	UUIDValue, err := json.Marshal(fileUUID)
	if err != nil {
		return File{}, uuid.Nil, err
	}
	fileHMACbytes := userlib.Argon2Key(UUIDValue, userlib.Hash(hmacSalt), 16)
	fileHMACUUID, err := uuid.FromBytes(fileHMACbytes)
	if err != nil {
		return File{}, uuid.Nil, err
	}

	actualHMACValue, ok := userlib.DatastoreGet(uuid.UUID(fileHMACUUID))
	if !ok {
		return File{}, uuid.Nil, errors.New("ActualHMAC does not exist")
	}

	equal := userlib.HMACEqual(calulatedHMACValue, actualHMACValue)
	if !equal {
		return File{}, uuid.Nil, errors.New("HMACs are not equal")
	}

	fileBytes := userlib.SymDec(encKey, fileEnc)
	err = json.Unmarshal(fileBytes, &fileBlock)
	if err != nil {
		return File{}, uuid.Nil, err
	}

	return fileBlock, fileHMACUUID, nil
}

func DecryptHMACInvInt(encKey []byte, HMACKey []byte, invIntUUID uuid.UUID, HMACUUID uuid.UUID) (invitationIntermediate InvitationIntermediate, err error) {
	invIntEnc, ok := userlib.DatastoreGet(invIntUUID)
	if !ok {
		return InvitationIntermediate{}, errors.New("UUID does not point to an invint")
	}

	calulatedHMACValue, err := userlib.HMACEval(HMACKey, invIntEnc)
	if err != nil {
		return InvitationIntermediate{}, err
	}

	actualHMACValue, ok := userlib.DatastoreGet(HMACUUID)
	if !ok {
		return InvitationIntermediate{}, errors.New("ActualHMAC does not exist")
	}

	equal := userlib.HMACEqual(calulatedHMACValue, actualHMACValue)
	if !equal {
		return InvitationIntermediate{}, errors.New("HMACs are not equal")
	}

	invIntBytes := userlib.SymDec(encKey, invIntEnc)
	err = json.Unmarshal(invIntBytes, &invitationIntermediate)
	if err != nil {
		return InvitationIntermediate{}, err
	}

	return invitationIntermediate, nil
}

func FileGeneratorHelper(fileStructNumber int, content []byte, slicelength int, fileEncryptKey []byte, fileHMACKey []byte, fileHMACSalt []byte, fileHeadUUID uuid.UUID) error {
	// we only need one file block as head
	// Initialize array to store all current file structures
	var fileArray []File = make([]File, int(fileStructNumber))
	// Intialize array to store all current uuids for each file
	var uuidArray []uuid.UUID = make([]uuid.UUID, int(fileStructNumber))

	// First generates UUIDS
	for i := 0; i < fileStructNumber; i += 1 {
		// Generates random UUID for file
		randomFileUUID := uuid.New()
		uuidArray[i] = randomFileUUID
	}

	if fileHeadUUID != uuid.Nil {
		uuidArray[0] = fileHeadUUID
	}

	// Next Generate File Blocks
	for i := 0; i < fileStructNumber; i += 1 {
		var currContent []byte
		if i == fileStructNumber-1 {
			currContent = content[i*slicelength:]
		} else {
			currContent = content[i*slicelength : (i*slicelength + slicelength)]
		}
		// Generates File struct and stores data in it
		var newFileBlock File
		newFileBlock.Content = currContent

		// Places File struct and UUID in respective place
		fileArray[i] = newFileBlock

		if i != fileStructNumber-1 {
			fileArray[i].NextFile = uuidArray[i+1]
		}

		if i == fileStructNumber-1 && i != 0 {
			fileArray[0].LastFile = uuidArray[i]
		}
	}

	// Iterate through FileBlocks, and Encrypt and HMAC them
	for i := 0; i < fileStructNumber; i += 1 {

		//filedataByte is the File struct turned into a byte for storage
		filedataByte, err := json.Marshal(fileArray[i])
		//Error message
		if err != nil {
			return err
		}
		//TODO: Encrypt File Struct
		IV := userlib.RandomBytes(16)
		filedataByteEnc := userlib.SymEnc(fileEncryptKey, IV, filedataByte)

		userlib.DatastoreSet(uuidArray[i], filedataByteEnc)

		//Calculate the HMAC of the File struct byte string
		HMACValue, err := userlib.HMACEval(fileHMACKey, filedataByteEnc)
		if err != nil {
			return err
		}

		// Generate a HMAC UUID
		UUIDValue, err := json.Marshal(uuidArray[i])
		if err != nil {
			return err
		}

		generatedHMACUUID := userlib.Argon2Key(UUIDValue, userlib.Hash(fileHMACSalt), 16)

		HMACUUID, err := uuid.FromBytes(generatedHMACUUID)

		// Store the HMAC'd user struct on dataStore
		userlib.DatastoreSet(HMACUUID, HMACValue)

	}
	return nil

}

func (userdata *User) GetHeadFile(filename string) ([]byte, []byte, uuid.UUID, []byte, File, error) {

	if userdata.OwnedFiles[filename] == uuid.Nil && userdata.InvitedFiles[filename] == uuid.Nil {
		return nil, nil, uuid.Nil, nil, File{}, errors.New("given filename dne in personal namespace of the caller")
	}

	var fileEncryptKey []byte
	var fileHMACKey []byte
	var fileheadUUID uuid.UUID
	var fileHMACSalt []byte

	if userdata.OwnedFiles[filename] != uuid.Nil {
		fileIntermediateUUID := userdata.OwnedFiles[filename]
		fileIntermediateEncKey := userdata.FileEncrypt[fileIntermediateUUID]
		fileIntermediateHMACKey := userdata.FileHMAC[fileIntermediateUUID]

		fileIntermediateEncrypted, ok := userlib.DatastoreGet(fileIntermediateUUID)
		if ok == false {
			return nil, nil, uuid.Nil, nil, File{}, errors.New("datastore couldnt find fileIntermediate")
		}

		fileIntermediateHMACEval, err := userlib.HMACEval(fileIntermediateHMACKey, fileIntermediateEncrypted)
		if err != nil {
			return nil, nil, uuid.Nil, nil, File{}, err
		}

		fileIntermediateHMACUUIDTemp := userlib.Argon2Key([]byte(userdata.Password+filename), userlib.Hash(fileIntermediateHMACKey), 16)
		fileIntermediateHMACUUID, err := uuid.FromBytes(fileIntermediateHMACUUIDTemp)
		if err != nil {
			return nil, nil, uuid.Nil, nil, File{}, err
		}

		actualFileIntermediateHMACEval, ok := userlib.DatastoreGet(fileIntermediateHMACUUID)
		if ok == false {
			return nil, nil, uuid.Nil, nil, File{}, errors.New("datastore couldnt find HMAC")
		}

		HMACEqual := userlib.HMACEqual(fileIntermediateHMACEval, actualFileIntermediateHMACEval)
		if !HMACEqual {
			return nil, nil, uuid.Nil, nil, File{}, errors.New("HMACVALUES NOT EQUAL TO STORED HMAC EVAL VALUE")
		}

		fileIntermediateDec := userlib.SymDec(fileIntermediateEncKey, fileIntermediateEncrypted)

		var fileIntermediateStruct FileIntermediate
		fileIntermptr := &fileIntermediateStruct
		json.Unmarshal(fileIntermediateDec, fileIntermptr)

		fileEncryptKey = fileIntermediateStruct.FileEncrypt
		fileHMACKey = fileIntermediateStruct.FileMac
		fileHMACSalt = fileIntermediateStruct.HMACUUIDSalt
		fileheadUUID = fileIntermediateStruct.FileUUID

	} else {
		fileIntermediateUUID := userdata.InvitedFiles[filename]
		fileIntermediateEncKey := userdata.FileEncrypt[fileIntermediateUUID]
		fileIntermediateHMACKey := userdata.FileHMAC[fileIntermediateUUID]

		fileIntermediateEncrypted, ok := userlib.DatastoreGet(fileIntermediateUUID)
		if ok == false {
			return nil, nil, uuid.Nil, nil, File{}, errors.New("datastore couldnt find invitationIntermediate")
		}

		fileIntermediateHMACEval, err := userlib.HMACEval(fileIntermediateHMACKey, fileIntermediateEncrypted)
		if err != nil {
			return nil, nil, uuid.Nil, nil, File{}, err
		}

		fileIntermediateHMACUUID := userdata.InvitedFiles[filename+"HMACUUID"]

		actualFileIntermediateHMACEval, ok := userlib.DatastoreGet(fileIntermediateHMACUUID)
		if ok == false {
			return nil, nil, uuid.Nil, nil, File{}, errors.New("datastore couldnt find HMAC")
		}

		HMACEqual := userlib.HMACEqual(fileIntermediateHMACEval, actualFileIntermediateHMACEval)
		if !HMACEqual {
			return nil, nil, uuid.Nil, nil, File{}, errors.New("HMACVALUES NOT EQUAL TO STORED HMAC EVAL VALUE")
		}

		fileIntermediateDec := userlib.SymDec(fileIntermediateEncKey, fileIntermediateEncrypted)

		var invitationIntermediateStruct InvitationIntermediate
		fileIntermptr := &invitationIntermediateStruct
		json.Unmarshal(fileIntermediateDec, fileIntermptr)

		fileEncryptKey = invitationIntermediateStruct.FileEncryptKey
		fileHMACKey = invitationIntermediateStruct.FileMACKey
		fileHMACSalt = invitationIntermediateStruct.HMACUUIDSalt
		fileheadUUID = invitationIntermediateStruct.FileHeadUUID

	}

	// File head
	var fileHead File
	fileHeadptr := &fileHead

	//Get the fileHeadEnc from datastore
	fileHeadEnc, ok := userlib.DatastoreGet(fileheadUUID)
	if ok == false {
		return nil, nil, uuid.Nil, nil, File{}, errors.New("datastore couldnt find headFile")
	}

	//HMAC it
	fileHeadHMAC, err := userlib.HMACEval(fileHMACKey, fileHeadEnc)
	if err != nil {
		return nil, nil, uuid.Nil, nil, File{}, err
	}

	// Generate a HMAC UUID
	UUIDValue, err := json.Marshal(fileheadUUID)
	if err != nil {
		return nil, nil, uuid.Nil, nil, File{}, err
	}

	//HMACUUIDc finder
	generatedHMACUUID := userlib.Argon2Key(UUIDValue, userlib.Hash(fileHMACSalt), 16)

	HMACUUID, err := uuid.FromBytes(generatedHMACUUID)
	if err != nil {
		return nil, nil, uuid.Nil, nil, File{}, err
	}

	HMACActualEval, ok := userlib.DatastoreGet(HMACUUID)

	if ok == false {
		return nil, nil, uuid.Nil, nil, File{}, errors.New("datastore couldnt find headFile")
	}

	equal := userlib.HMACEqual(fileHeadHMAC, HMACActualEval)
	if !equal {
		return nil, nil, uuid.Nil, nil, File{}, errors.New("fileHead HMACVALUE NOT EQUAL TO STORED HMAC EVAL VALUE")
	}

	//Decrypt the head file structure first
	//Put the resultant in fileHead
	err = json.Unmarshal(userlib.SymDec(fileEncryptKey, fileHeadEnc), fileHeadptr)
	if err != nil {
		return nil, nil, uuid.Nil, nil, File{}, err
	}
	return fileEncryptKey, fileHMACKey, fileheadUUID, fileHMACSalt, fileHead, err
}

func (userdata *User) GetIntermediateFile(filename string) (fileIntermediate FileIntermediate, err error) {
	if userdata.OwnedFiles[filename] == uuid.Nil {
		return FileIntermediate{}, errors.New("given filename dne in personal namespace of the caller")
	}

	var fileIntermediateStruct FileIntermediate
	fileIntermptr := &fileIntermediateStruct

	if userdata.OwnedFiles[filename] != uuid.Nil {
		fileIntermediateUUID := userdata.OwnedFiles[filename]
		fileIntermediateEncKey := userdata.FileEncrypt[fileIntermediateUUID]
		fileIntermediateHMACKey := userdata.FileHMAC[fileIntermediateUUID]

		fileIntermediateEncrypted, ok := userlib.DatastoreGet(fileIntermediateUUID)
		if ok == false {
			return FileIntermediate{}, errors.New("datastore couldnt find fileIntermediate")
		}

		fileIntermediateHMACEval, err := userlib.HMACEval(fileIntermediateHMACKey, fileIntermediateEncrypted)
		if err != nil {
			return FileIntermediate{}, err
		}

		fileIntermediateHMACUUIDTemp := userlib.Argon2Key([]byte(userdata.Password+filename), userlib.Hash(fileIntermediateHMACKey), 16)
		fileIntermediateHMACUUID, err := uuid.FromBytes(fileIntermediateHMACUUIDTemp)
		if err != nil {
			return FileIntermediate{}, err
		}

		actualFileIntermediateHMACEval, ok := userlib.DatastoreGet(fileIntermediateHMACUUID)
		if ok == false {
			return FileIntermediate{}, errors.New("datastore couldnt find HMAC")
		}

		HMACEqual := userlib.HMACEqual(fileIntermediateHMACEval, actualFileIntermediateHMACEval)
		if !HMACEqual {
			return FileIntermediate{}, errors.New("HMACVALUES NOT EQUAL TO STORED HMAC EVAL VALUE")
		}

		fileIntermediateDec := userlib.SymDec(fileIntermediateEncKey, fileIntermediateEncrypted)

		json.Unmarshal(fileIntermediateDec, fileIntermptr)
	}

	return fileIntermediateStruct, nil

}

func (userdata *User) GetInvitationIntermediate(filename string) (invitationIntermediate InvitationIntermediate, err error) {
	if userdata.InvitedFiles[filename] == uuid.Nil {
		return InvitationIntermediate{}, errors.New("Filename does not exist in invited dict")
	}

	fileIntermediateUUID := userdata.InvitedFiles[filename]
	fileIntermediateEncKey := userdata.FileEncrypt[fileIntermediateUUID]
	fileIntermediateHMACKey := userdata.FileHMAC[fileIntermediateUUID]

	fileIntermediateEncrypted, ok := userlib.DatastoreGet(fileIntermediateUUID)
	if ok == false {
		return InvitationIntermediate{}, errors.New("datastore couldnt find invitationIntermediate")
	}

	fileIntermediateHMACEval, err := userlib.HMACEval(fileIntermediateHMACKey, fileIntermediateEncrypted)
	if err != nil {
		return InvitationIntermediate{}, err
	}

	fileIntermediateHMACUUID := userdata.InvitedFiles[filename+"HMACUUID"]

	actualFileIntermediateHMACEval, ok := userlib.DatastoreGet(fileIntermediateHMACUUID)
	if ok == false {
		return InvitationIntermediate{}, errors.New("datastore couldnt find HMAC")
	}

	HMACEqual := userlib.HMACEqual(fileIntermediateHMACEval, actualFileIntermediateHMACEval)
	if !HMACEqual {
		return InvitationIntermediate{}, errors.New("HMACVALUES NOT EQUAL TO STORED HMAC EVAL VALUE")
	}

	fileIntermediateDec := userlib.SymDec(fileIntermediateEncKey, fileIntermediateEncrypted)

	var invitationIntermediateStruct InvitationIntermediate
	fileIntermptr := &invitationIntermediateStruct
	json.Unmarshal(fileIntermediateDec, fileIntermptr)

	return invitationIntermediateStruct, nil
}
