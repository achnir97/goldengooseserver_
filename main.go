package main

import (
	"fmt"
	"encoding/json"
	"log"
	"net/http"
	"github.com/achnir97/server/config"
)

type User struct {
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
		Email     string `json:"email"`
		Password  string `json:"password"`
	}

func main() {

	http.HandleFunc("/register", register)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
func register(w http.ResponseWriter, r *http.Request) {
	db, err:=config.Connect()

	var user User
	err = json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	db.Exec("INSERT INTO users (first_name, last_name, email, password) VALUES ($1, $2, $3, $4)", user.FirstName, user.LastName, user.Email, user.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "User %s %s created successfully!", user.FirstName, user.LastName)
}



/*
func signupHandler(db *gorm.DB) http.HandlerFunc{
	return func(w http.ResponseWriter, r *http.Request) {
		var user User
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		user.Password = string(hashedPassword)
		err = db.Create(&user).Error
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]int{"id": int(user.ID)})
	}
}*/

