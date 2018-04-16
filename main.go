package main

import (
  "fmt"
  "log"
  "net/http"
  "encoding/json"
  "database/sql"
  _ "github.com/mattn/go-sqlite3"
  "golang.org/x/crypto/sha3"
)

func main() {

  setupDatabase()

	http.HandleFunc("/auth", auth)
  http.HandleFunc("/add", add)

  log.Println("Listening on port 8080.")
	logError(http.ListenAndServe(":8080", nil))
}

func logError(err error) {
	if err != nil {
		log.Println(err)
	}
}

type User struct {
  Id []uint8
  Username string
  Password string
  Token string
}

type Credentails struct {
  Username string
  Password string
}

func database() *sql.DB {

	database, error := sql.Open("sqlite3", "./authbase.db")
	logError(error)

	return database
}

func setupDatabase() {

	statement, _ := database().Prepare("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT NOT NULL, password TEXT NOT NULL, token TEXT)")
	_, error := statement.Exec()
	logError(error)
}

func add(w http.ResponseWriter, r *http.Request) {

  user := User{}

  decoder := json.NewDecoder(r.Body)

  err := decoder.Decode(&user)
  if err != nil {
    logError(err)
    fmt.Fprintf(w, "Failed to add user.")
    return
  }

  defer r.Body.Close()

  rows, err := database().Query("INSERT INTO users (username, password, token) VALUES (?, ?, ?)",
    user.Username, user.Password, generateToken(user.Password))
  if err != nil {
    logError(err)
    fmt.Fprintf(w, "Failed to add user.")
    return
  }

  defer rows.Close()
  for rows.Next() {
    err := rows.Scan(&user)
    logError(err)
    return
  }

  logError(rows.Err())

  json, err := json.Marshal(user)
  if err != nil {
    logError(err)
    fmt.Fprintf(w, "Failed to create user.")
    return
  }

  fmt.Fprintf(w, string(json))
}

func auth(w http.ResponseWriter, r *http.Request) {

  // Decode request body into credentials

  cred := Credentails{}

  decoder := json.NewDecoder(r.Body)

  err := decoder.Decode(&cred)
  if err != nil {
    logError(err)
    fmt.Fprintf(w, "Failed to decode body.")
    return
  }

  defer r.Body.Close()

  rows, err := database().Query("SELECT 'id', 'username', 'token' FROM users WHERE username=? AND password=?",
    cred.Username, cred.Password)
  if err != nil {
    logError(err)
    fmt.Fprintf(w, "No user found with given credentials.")
    return
  }

  defer rows.Close()

  user := User{}
  for rows.Next() {
		scanError := rows.Scan(&user.Id, &user.Username, &user.Token)
		logError(scanError)
	}

  logError(rows.Err())

  if len(user.Token) == 0 {
    fmt.Fprintf(w, "No user found with given credentials.")
    return
  }

  w.Header().Set("Content-Type", "application/json")

  token := make(map[string]string)
  token["token"] = user.Token

  json, err := json.Marshal(token)
  if err != nil {
    logError(err)
    fmt.Fprintf(w, "Failed to generate token")
    return
  }

  fmt.Fprintf(w, string(json))
  log.Println(string(json))
}

func generateToken(password string) string {
  k := []byte("DenneStrengen-erVeldigHemmeling, La oss bruke mye tegn/bokstaver & tall[]{1,5,3,2..2-33}")
  buf := []byte(password)
  // A MAC with 32 bytes of output has 256-bit security strength -- if you use at least a 32-byte-long key.
  h := make([]byte, 32)
  d := sha3.NewShake256()
  // Write the key into the hash.
  d.Write(k)
  // Now write the data.
  d.Write(buf)
  // Read 32 bytes of output from the hash into h.
  d.Read(h)
  // Convert the bytes array to a string
  token := fmt.Sprintf("%x", h)
  // Return the token converted to a string
  return token
}
