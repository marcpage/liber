package libernetlib

import (
	"fmt"
	"io/ioutil"
	"log"
	"crypto/sha256"
	"os"
	"compress/zlib"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

func read_file_contents(path string) (contents []byte, err error) {
	file_to_read, err := os.Open(path)
	if err != nil {
		return
	}
	defer file_to_read.Close()
	contents, err = ioutil.ReadAll(file_to_read)
	return
}

func hash_data(data []byte) (hash []byte) {
	hasher := sha256.New()
	hasher.Write(data)
	hash = hasher.Sum(nil)
	return
}

func hash_data_hex(data []byte) (hash string) {
	hash = fmt.Sprintf("%x", hash_data(data))
	return
}

func compress_data(data []byte) (compressed []byte, err error) {
	var buffer bytes.Buffer
	writer, err := zlib.NewWriterLevel(&buffer, zlib.BestCompression)
	if err != nil {
		return
	}
	writer.Write(data)
	writer.Close()
	compressed = buffer.Bytes()
	return
}

func decompress_data(data []byte) (original []byte, err error) {
	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return
	}
	original, err = ioutil.ReadAll(reader)
	reader.Close()
	return
}

func encrypt_data(data []byte, key []byte) (encrypted []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	var padded []byte
	padded = append(padded,data...)
	padded = append(padded, 0, 1)
	for len(padded) % aes.BlockSize != 0 {
		padded = append(padded, 2)
	}
	iv := key[:aes.BlockSize]
	encrypted = make([]byte, len(padded))
	cryptor := cipher.NewCBCEncrypter(block, iv)
	cryptor.CryptBlocks(encrypted, padded)
	return
}

func strip_data_tail(data []byte) (stripped []byte, err error) {
	index := len(data) - 2
	for index > 0 {
		if data[index] == 0 && data[index + 1] == 1 {
			stripped = data[:index]
			return
		}
		index = index - 1
	}
	err = errors.New("tail overflow")
	return
}

func decrypt_data(data []byte, key []byte) (decrypted []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	iv := key[:aes.BlockSize]
	if len(data)%aes.BlockSize != 0 {
		err = errors.New("ciphertext is not a multiple of the block size")
		return
	}
	decryptor := cipher.NewCBCDecrypter(block, iv)
	decrypted_buffer := make([]byte, len(data))
	decryptor.CryptBlocks(decrypted_buffer, data)
	decrypted, err = strip_data_tail(decrypted_buffer)
	return
}

func package_data(data []byte) (block []byte, name []byte, key []byte, err error) {
	key = hash_data(data)
	compressed, err := compress_data(data)
	if err != nil {
		return
	}
	encrypted, err := encrypt_data(compressed, key)
	block = append([]byte{120}, encrypted...)
	if err != nil {
		return
	}
	name = hash_data(block)
	return
}

func unpackage_data(data []byte, key []byte) (unpackaged []byte, err error) {
	if data[0] != 120 {
		err = errors.New("unpackage of data that was not packaged")
		return
	}
	decrypted, err := decrypt_data(data[1:], key)
	if err != nil {
		return
	}
	unpackaged, err = decompress_data(decrypted)
	return
}

func increment_block(block []byte) (valid bool) {
	valid = false
	for index, value := range block {
		if value < 255 {
			block[index] = value + 1
			valid = true
			break
		} else {
			block[index] = 2
		}
	}
	return
}

// TODO: Calculate distance in bits
func hash_distance(hash1 []byte, hash2 []byte) (distance int) {
	for index, value := range hash1 {
		if value != hash2[index] {
			distance = index * 8
			return
		}
	}
	distance = len(hash1) * 8
	return
}

// TODO: parallelize looking for adjustment blocks, pass in initialization block with last digit different
func pack_data(data []byte, sibling []byte, relation int) (block []byte, name []byte, err error) {
	compressed, err := compress_data(data)
	if err != nil {
		return
	}
	raw_block := append(append([]byte{160}, compressed...), 0, 1)
	adjustment := []byte{2,2,2,2,2,2,2,2}
	for {
		source_data := raw_block
		if sibling != nil {
			source_data = append(source_data, adjustment...)
			if !increment_block(adjustment) {
				log.Fatal("block wrap around")
			}
		}
		name = hash_data(source_data)
		if sibling == nil || hash_distance(name, sibling) >= relation {
			block = source_data
			break
		}
	}
	return
}

func unpack_data(data []byte) (unpacked []byte, err error) {
	if data[0] != 160 {
		err = errors.New("unpack of data that was not packed")
		return
	}
	stripped, err := strip_data_tail(data[1:])
	if err != nil {
		return
	}
	unpacked, err = decompress_data(stripped)
	return
}

func test_package(data []byte) {
	package_block, _, key, err := package_data(data)
	if err != nil {
		log.Fatal(err)
	}
	unpackaged_contents, err := unpackage_data(package_block, key)
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(unpackaged_contents, data) {
		log.Fatal("Unpackaged contents do not match")
	}
	fmt.Printf("\tPackage Pass\n")
}

func test_pack(data []byte, sibling []byte, relation int) {
	pack_block, pack_name, err := pack_data(data, sibling, relation)
	if err != nil {
		log.Fatal(err)
	}
	unpacked_contents, err := unpack_data(pack_block)
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(unpacked_contents, data) {
		log.Fatal("Unpacked contents do not match")
	}
	if hash_distance(pack_name, sibling) < relation {
		log.Fatal("Distance too short %x vs %x = %d instead of %d", pack_name, sibling, hash_distance(pack_name, sibling), relation)
	}
	fmt.Printf("\tPack Pass\n")
}

func test_compress(data []byte) {
	compressed, err := compress_data(data)
	if err != nil {
		log.Fatal(err)
	}
	contents_from_compressed, err := decompress_data(compressed)
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(contents_from_compressed, data) {
		log.Fatal("Compressed contents do not match")
	}
	fmt.Printf("\tCompression Pass\n")
}

func test_cryption(data []byte) {
	key := hash_data(data)
	encrypted,err := encrypt_data(data, key)
	if err != nil {
		log.Fatal(err)
	}
	decrypted,err := decrypt_data(encrypted, key)
	if err != nil {
		log.Fatal(err)
	}
	if !bytes.Equal(decrypted, data) {
		fmt.Printf("     data[%d] = % x\nencrypted[%d] = % x\ndecrypted[%d] = % x\n",
					len(data), data, len(encrypted), encrypted, len(decrypted), decrypted)
		log.Fatal("Decrypted contents do not match")
	}
	fmt.Printf("\tEncryption Pass\n")
}

func main() {
	sibling := hash_data([]byte{})
    for _, arg := range os.Args[1:] {
		contents, err := read_file_contents(arg)
		if err != nil {
			log.Fatal(err)
		}
		package_block, package_name, key, err := package_data(contents)
		if err != nil {
			log.Fatal(err)
		}
		pack_block, pack_name, err := pack_data(contents, sibling, 16)
		if err != nil {
			log.Fatal(err)
		}
		unpacked_contents, err := unpack_data(pack_block)
		if err != nil {
			log.Fatal(err)
		}
		if !bytes.Equal(unpacked_contents, contents) {
			log.Fatal("Unpacked contents do not match")
		}
		compressed, err := compress_data(contents)
		if err != nil {
			log.Fatal(err)
		}
    	fmt.Printf("%s\n", arg)
    	fmt.Printf("\t %x %x %x\n", pack_name, package_name, key)
		fmt.Printf("\t size = %d bytes, compressed size = %d bytes, package block size = %d, pack block size = %d\n",
						len(contents), len(compressed), len(package_block), len(pack_block))
		test_compress(contents)
		test_cryption(contents)
		test_pack(contents, sibling, 16)
		test_package(contents)
    }
}

/*

type PackageEntry struct {
	size uint64
	sha256 string
	parts string
}

type Package struct {
	files map[string]PackageEntry
}

type SignedWrapper struct {
}

encoding/json

type Message struct {
    Name string
    Body string
    Time int64
}

m := Message{"Alice", "Hello", 1294706395881547000}

b == []byte(`{"Name":"Alice","Body":"Hello","Time":1294706395881547000}`)

var m Message

err := json.Unmarshal(b, &m)

m = Message{
    Name: "Alice",
    Body: "Hello",
    Time: 1294706395881547000,
}

func IsDirectory(path string) (bool, error) {
    fileInfo, err := os.Stat(path)
    if err != nil {
      return false, err
    }
    return fileInfo.Mode().IsDir(), err
    return fileInfo.Mode().IsRegular(), err
}

*/
