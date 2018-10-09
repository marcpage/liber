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

type NamedData struct {
	name string
	data []byte
}

type DataRequest struct {
	request string
    response chan <- NamedData
}

func Store(path string, putRequests chan <- NamedData, getRequests chan <- DataRequest) {
}
