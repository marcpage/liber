package libernetlib

import (
	"fmt"
	"net/http"
	"strings"
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

func serve(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, world. %s %s %s %s %s", r.Method, r.Proto, r.Host, r.RemoteAddr, r.RequestURI)
}

func serveBlocks(w http.ResponseWriter, r *http.Request) {
	var parts = strings.Split(r.RequestURI, "/")
	if len(parts) == 3 {
		fmt.Fprintf(w, "Hello, world. %s %d", parts[len(parts)-1], len(parts))
	}
}

func main() {
	http.HandleFunc("/", serve)
	http.HandleFunc("/sha256/", serveBlocks)
	http.ListenAndServe(":1234", nil)
}
