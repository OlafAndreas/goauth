package main

import (
  "io"
  "fmt"
  "log"
  "errors"
  "net/http"
  "crypto/aes"
  "crypto/rand"
  "database/sql"
  "encoding/json"
  "crypto/cipher"
  "encoding/base64"
  "golang.org/x/crypto/sha3"
  _ "github.com/mattn/go-sqlite3"
)

const AppSecret = "AFY5S9BEU54FOG3X3WBQA81ZACG58GQ6"

func main() {

  setupDatabase()
  /*
  value := []byte("Here's Olaf!")
  fmt.Printf("%s\n", value)
  enc, err := encrypt(value)
  if err != nil {
    logError(err)
  }
  fmt.Printf("%0x\n", enc)
  dec, err := decrypt(enc)
  if err != nil {
    logError(err)
  }
  fmt.Printf("%s\n", dec)*/


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
  Id int64
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

	statement, _ := database().Prepare("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE, username TEXT NOT NULL, password TEXT NOT NULL, token TEXT NOT NULL DEFAULT '')")
	_, error := statement.Exec()
	logError(error)
}

func add(w http.ResponseWriter, r *http.Request) {

  user := User{}

  decoder := json.NewDecoder(r.Body)

  err := decoder.Decode(&user)
  if err != nil {
    log.Println("Error when decoding user in add.")
    logError(err)
    fmt.Fprintf(w, "Failed to add user.")
    return
  }

  defer r.Body.Close()

  statement, err := database().Prepare("INSERT INTO users (username, password) VALUES (?, ?)")
  if err != nil {
    log.Println("Error when creating query in add.")
    logError(err)
    fmt.Fprintf(w, "Failed to add user.")
    return
  }
  user.Password = generateHash(user.Password)

  res, err := statement.Exec(user.Username, user.Password)
  if err != nil {
    logError(err)
    log.Println("Unable to store user.")
    return
  }

  id, err := res.LastInsertId()
  if err != nil {
    logError(err)
    log.Println("Error fetching last inserted id")
    return
  }

  user.Id = id

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

  // Create a json decoder with content from the request body
  decoder := json.NewDecoder(r.Body)

  // Decode the content into the cred struct
  err := decoder.Decode(&cred)
  if err != nil {
    logError(err)
    fmt.Fprintf(w, "Failed to decode body.")
    return
  }

  // Close the body reader
  defer r.Body.Close()

  // Fetch information from users where credentials match
  rows, err := database().Query("SELECT id, username, token FROM users WHERE username=? AND password=?",
    cred.Username, generateHash(cred.Password))
  if err != nil {
    logError(err)
    fmt.Fprintf(w, "No user found with given credentials.")
    return
  }

  // Close the rows reader
  defer rows.Close()

  // Scan for user from rows
  user := User{}

  for rows.Next() {
		scanError := rows.Scan(&user.Id, &user.Username, &user.Token)
		logError(scanError)
	}

  logError(rows.Err())

  if len(user.Token) == 0 {
    user.Token = getToken(user)

    _, err := database().Exec(`UPDATE "users" SET token = ? WHERE id = ?`,
      user.Token, user.Id)
    if err != nil {
      logError(err)
    }
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

func getUser(token string) (User, error) {

  user := User{}

  rows, err := database().
  Query("SELECT 'id', 'username', 'token' FROM users WHERE token=?",
    token)
  if err != nil {
    logError(err)
    return user, err
  }

  defer rows.Close()

  for rows.Next() {
		scanError := rows.Scan(&user.Id, &user.Username, &user.Token)
    if scanError != nil {
      logError(scanError)
      log.Println("Unable to fetch data for user with token: " + token)
      return user, err
    }
	}

  return user, nil
}

// Retrieves a token based on the user.id and the app secret
func getToken(user User) string {
  return generateHash(string(user.Id) + ":" + AppSecret)
}

// Generates a sha3 hash based on the passed value salted with the AppSecret
func generateHash(value string) string {
  buf := []byte(value)
  // A MAC with 32 bytes of output has 256-bit security strength
  // -- if you use at least a 32-byte-long key.
  h := make([]byte, 32)
  d := sha3.NewShake256()
  // Write the key into the hash.
  d.Write([]byte(AppSecret))
  // Now write the data.
  d.Write(buf)
  // Read 32 bytes of output from the hash into h.
  d.Read(h)
  // Convert the bytes array to a string
  hash := fmt.Sprintf("%x", h)
  // Return the hash converted to a string
  return hash
}

func encrypt(text []byte) ([]byte, error) {
    block, err := aes.NewCipher([]byte(AppSecret))
    if err != nil {
        return nil, err
    }
    b := base64.StdEncoding.EncodeToString(text)
    ciphertext := make([]byte, aes.BlockSize+len(b))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return nil, err
    }
    cfb := cipher.NewCFBEncrypter(block, iv)
    cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
    return ciphertext, nil
}

func decrypt(text []byte) ([]byte, error) {
    block, err := aes.NewCipher([]byte(AppSecret))
    if err != nil {
        return nil, err
    }
    if len(text) < aes.BlockSize {
        return nil, errors.New("ciphertext too short")
    }
    iv := text[:aes.BlockSize]
    text = text[aes.BlockSize:]
    cfb := cipher.NewCFBDecrypter(block, iv)
    cfb.XORKeyStream(text, text)
    data, err := base64.StdEncoding.DecodeString(string(text))
    if err != nil {
        return nil, err
    }
    return data, nil
}
