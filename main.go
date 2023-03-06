package main

import (
	"fmt"
	"encoding/json"
	"log"
	"net/http"
	"github.com/achnir97/server/config"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"github.com/gorilla/mux"
	"github.com/rs/cors"	
)

type User struct {
	   gorm.Model
	    //ID uuid.UUID `gorm:"type:uuid;primary_key"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
		Email     string `json:"email"`
		Password  string `json:"password"`
		Date 	 string `json:"date"`
		NumberofGoose string `json:"numberofgoose"`
	}

func main() {
	r := mux.NewRouter()

	// Register the endpoints with gorilla/mux router
	r.HandleFunc("/register", register).Methods(http.MethodPost)
	r.HandleFunc("/signin", Signin).Methods(http.MethodPost)
	r.HandleFunc("/calculate/{email}", Calculate).Methods(http.MethodGet)
	
	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"},
		AllowedMethods:   []string{"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowCredentials: true,
	}).Handler(r)
	log.Fatal(http.ListenAndServe(":8080", corsHandler))	
}

func register(w http.ResponseWriter, r *http.Request) {
    db, err := config.Connect() // connects to the database
    migrator := db.Migrator() // check if the database exist or not 

    if migrator.HasTable(&User{}) { // first checks if the table exist or not 
        fmt.Println("Table 'users' already exists") 
    } else {
        // Create the users table
        err := db.AutoMigrate(&User{})
        if err != nil {
            panic(err)
        }
        fmt.Println("Table 'users' created successfully")
    }
    var user User
    err = json.NewDecoder(r.Body).Decode(&user)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // Hash the password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Store the hashed password in the database
    db.Exec("INSERT INTO users (first_name, last_name, email, password,date, numberof_goose) VALUES ($1, $2, $3, $4, $5,$6)", user.FirstName, user.LastName, user.Email, string(hashedPassword),user.Date, user.NumberofGoose)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    fmt.Fprintf(w, "User %s %s created successfully!", user.FirstName, user.LastName)
}



func Signin(w http.ResponseWriter, r *http.Request) {
	// Connect to the database
	db, err := config.Connect()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse the request body
	var user User
	err = json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Check if user exists in the database
	var existingUser User
	db.Where("email = ?", user.Email).First(&existingUser)
	if existingUser.Email == "" {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		fmt.Println("the email is empty")
		return
	}
	// Compare the passwords
	  if err := bcrypt.CompareHashAndPassword([]byte(existingUser.Password), []byte(user.Password)); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		fmt.Printf("existingUser.Password:  %s\n", []byte(existingUser.Password))
		fmt.Printf("Error is %s\n", err)
		return
	}
	// Successful login
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "You are now logged in!")
}


func Calculate(w http.ResponseWriter, r *http.Request) {
  // Parse the user ID from the request parameters
		vars := mux.Vars(r) // it reads the data in
		email:=vars["email"]
		fmt.Printf(email)
	// Connect to the database
		db, err := config.Connect()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
   // Execute the raw SQL query
		var numberofgoose int
		data := db.Raw("SELECT numberof_goose FROM users WHERE email = ?", email).Scan(&numberofgoose)
		if data.Error != nil {
			http.Error(w, data.Error.Error(), http.StatusInternalServerError)
			return
	}// Send the response back to the client
	response := map[string]int{"gooseCount": numberofgoose}
	json.NewEncoder(w).Encode(response)
	fmt.Println(response)
}

func LattestId(w http.ResponseWriter, r *http.Request){
	db, err:=config.Connect()
	if err!=nil{
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	var email string 
	data:=db.Raw("SELECT numberof_goose from users WHERE email=?",email).Scan(&email)
	if data.Error!=nil {
		http.Error(w, data.Error.Error(), http.StatusInternalServerError)
		return 
	}
	response:=map[string]string {"email":email}
	json.NewEncoder(w).Encode(response)
	fmt.Println(response)
	}

func corsMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Call the next handler
		h.ServeHTTP(w, r)
	})
}

