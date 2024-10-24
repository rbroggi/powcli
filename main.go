package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/uuid"
)

func main() {
	// Define flags
	filePath := flag.String("file", "", "Path to the file")
	userUUID := flag.String("uuid", "", "UUID string")
	difficulty := flag.Uint("difficulty", 0, "Difficulty as uint32")

	// Parse flags
	flag.Parse()

	// Validate flags
	if *filePath == "" || *userUUID == "" || *difficulty == 0 {
		log.Fatalf("Usage: %s -file <file path> -uuid <uuid> -difficulty <uint32>", os.Args[0])
	}
	// Read file into a byte slice
	fileData, err := os.ReadFile(*filePath)
	if err != nil {
		log.Fatalf("Failed to read file: %v", err)
	}

	fileDataHash := sha256.Sum256(fileData)

	// Decode UUID string into a 16-byte slice
	parsedUUID, err := uuid.Parse(*userUUID)
	if err != nil {
		log.Fatalf("Failed to parse UUID: %v", err)
	}
	uuidBytes := parsedUUID[:]
	zeroDifficulty := sha256.Sum256(append(fileDataHash[:], uuidBytes...))
	fmt.Printf("File data hash: %x\n", fileDataHash)
	fmt.Printf("user-id uuid bytes: %v\n", uuidBytes)
	fmt.Printf("Hex(hash(segment hash | user-id)): %s\n", hex.EncodeToString(zeroDifficulty[:]))
	fmt.Printf("difficulty string: %d\n", *difficulty)
	fmt.Printf("Solution: %d\n", PoW(append(fileDataHash[:], uuidBytes...), uint32(*difficulty)))
}

// PoW is a simple proof of work function that takes a byte slice and a difficulty
// and returns a nonce that satisfies the difficulty.
// The difficulty is the number of leading zeros bits in the hash of the input and nonce.
func PoW(input []byte, difficulty uint32) uint64 {
	for nonce := uint64(0); ; nonce++ {
		hash := sha256.Sum256(append(Uint64ToBytes(nonce), input...))
		if checkDifficulty(hash[:], difficulty) {
			return nonce
		}
		nonce++
	}
}

func Uint64ToBytes(n uint64) []byte {
	bytes := make([]byte, 8)
	binary.BigEndian.PutUint64(bytes, n)
	return bytes
}

func checkDifficulty(hash []byte, difficulty uint32) bool {
	// check if the first difficulty bits are zeros
	for i := 0; i < int(difficulty); i++ {
		// hash[i/8] gets the byte that contains the i-th bit
		// 1<<(7-uint(i%8)) creates a byte with the i-th bit set
		// the two are ANDed to check if the i-th bit is set
		if hash[i/8]&(1<<(7-uint(i%8))) != 0 {
			return false
		}
	}
	return true
}
