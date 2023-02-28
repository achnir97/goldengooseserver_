package config

import (
	"fmt"
	_"net/http"
	_"io/ioutil"
	"gorm.io/gorm"
	_"encoding/json"
	_"sync"
	"gorm.io/driver/postgres"
	"github.com/joho/godotenv"
	_"strconv"
	"os"
	
	
)

type Config struct {
	User     string
	Password string
	Host     string
	Port     string
	DbName   string
	SslMode  string
}

func Connect() (*gorm.DB, error) {
	err:=godotenv.Load(".env")
	if err!=nil{
	 fmt.Println(err)
	}
	dbUser:=os.Getenv("USERNAME")
	dbPassword:=os.Getenv("PASSWORD")
	dbIP:=os.Getenv("DBIP")
	dbPort :=os.Getenv("DBPORT")
	dbName:=os.Getenv("DBNAME")
	dbSslMode:=os.Getenv("DBSSLMODE")
	 
	dbConfig:= Config{
		User:dbUser,
		Password:dbPassword,
		Host:dbIP,
		Port:dbPort,
		DbName:dbName,
		SslMode:dbSslMode,
	}
	
	dsn := fmt.Sprintf("user=%s password=%s host=%s port=%s dbname=%s sslmode=%s", dbConfig.User, dbConfig.Password, dbConfig.Host, dbConfig.Port, dbConfig.DbName, dbConfig.SslMode)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		fmt.Println("The database couldn't be connected, Check your error properly")
		return nil, err
	}
	fmt.Println("The database is connected")
	return db, nil
}
