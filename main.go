package main

import (
  "fmt"
  "log"
  "net/http"
  "encoding/json"
)

func main() {

	http.HandleFunc("/auth", auth)
	logError(http.ListenAndServe(":8080", nil))
  fmt.Println("Listening on port 8080.")
}

func logError(err error) {
	if err != nil {
		log.Println(err)
	}
}

type credentails struct {
  Username string
  Password string
}

func auth(w http.ResponseWriter, r *http.Request) {

  // Decode request body into credentials

  cred := credentails{}

  decoder := json.NewDecoder(r.Body)

  err := decoder.Decode(&cred)
  if err != nil {
    logError(err)
    fmt.Fprintf(w, "Failed to decode body.")
  }

  defer r.Body.Close()
  w.Header().Set("Content-Type", "application/json")

  token := make(map[string]string)
  token["token"] = "SomeLongHashesTokenToUseInBearer"

  json, err := json.Marshal(token)
  if err != nil {
    logError(err)
    fmt.Fprintf(w, "Failed to generate token")
  }

  fmt.Fprintf(w, string(json))
  fmt.Println(string(json))
}
