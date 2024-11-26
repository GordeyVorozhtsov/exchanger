package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/locales/currency"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Mail     string `json:"mail" binding:"required"`
	Password string `json:"password" binding:"required"`
}

var db *sql.DB
var jwtKey = []byte("secret_key")

// Инициализация базы данных
func initDB() {
	var err error
	db, err = sql.Open("postgres", "user=fucku dbname=currencies sslmode=disable")
	if err != nil {
		panic("problem with connection to DB: " + err.Error())
	}
}

type Claims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

// Генерация JWT токена
func GenerateToken(email string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Email: email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// Middleware для проверки авторизации
func TokenAuthMiddleware(c *gin.Context) {
	tokenString := c.Request.Header.Get("Authorization")
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is missing"})
		c.Abort()
		return
	}
	tokenString = tokenString[len("Bearer "):] // Удаляем "Bearer " из токена
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		c.Abort()
		return
	}
	c.Set("email", claims.Email) // Сохраняем email в контексте запроса
	c.Next()
}

func register(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Хешируем пароль
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not hash password"})
		return
	}

	// Записываем пользователя в базу данных
	_, err = db.Exec(`INSERT INTO users (email, password_hash) VALUES ($1, $2)`, user.Mail, passwordHash)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to register user: " + err.Error()})
		return
	}

	// Записываем в таблицу users_wallet
	_, err = db.Exec(`INSERT INTO users_wallet (email) VALUES ($1)`, user.Mail)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unable to write in users_wallet db: " + err.Error()})
		return
	}

	fmt.Printf("User added: %s\n", user.Mail)
	c.JSON(http.StatusOK, gin.H{"message": "registration successful", "user": user.Mail})
}

func login(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Получение хеша пароля по email
	var passwordHash string
	err := db.QueryRow(`SELECT password_hash FROM users WHERE email = $1`, user.Mail).Scan(&passwordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not query user"})
		return
	}

	// Проверка соответствия пароля хешу
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(user.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Генерация токена
	token, err := GenerateToken(user.Mail)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": token})
}

func profile(c *gin.Context) {
	email := c.MustGet("email").(string) // Получаем email из контекста
	c.JSON(http.StatusOK, gin.H{"email": email})
}

func balance(c *gin.Context) {
	token := c.Request.Header.Get("Authorization")
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "token not provided"})
		return
	}
	email := c.MustGet("email").(string)
	var rub, usd, eur float64

	err := db.QueryRow("SELECT rub, usd, eur FROM users_wallet WHERE email = $1", email).Scan(&rub, &usd, &eur)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "no data found for this user"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not get balance"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"email": email, "rub": rub, "usd": usd, "eur": eur})
}
func deposit(c *gin.Context) {
	var err error
	token := c.Request.Header.Get("Authorization")
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "token not provided"})
		return
	}
	email := c.MustGet("email").(string) // Получаем email пользователя из контекста

	var request struct {
		Amount   float64 `json:"amount" binding:"required"`
		Currency string  `json:"currency" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Обновление баланса в зависимости от валюты
	var result sql.Result
	switch request.Currency {
	case "rub":
		result, err = db.Exec("UPDATE users_wallet SET rub = rub + $1 WHERE email = $2", request.Amount, email)
	case "usd":
		result, err = db.Exec("UPDATE users_wallet SET usd = usd + $1 WHERE email = $2", request.Amount, email)
	case "eur":
		result, err = db.Exec("UPDATE users_wallet SET eur = eur + $1 WHERE email = $2", request.Amount, email)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid currency"})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not update balance: " + err.Error()})
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "update failed, check if the user exists"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"email": email, "message": "deposit successful", "currency": request.Currency, "amount": request.Amount})
}
func withdraw(c *gin.Context) {
	var err error
	token := c.Request.Header.Get("Authorization")
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "token not provided"})
		return
	}
	email := c.MustGet("email").(string) // Получаем email пользователя из контекста

	var request struct {
		Amount   float64 `json:"amount" binding:"required"`
		Currency string  `json:"currency" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Обновление баланса в зависимости от валюты
	var result sql.Result
	switch request.Currency {
	case "rub":
		result, err = db.Exec("UPDATE users_wallet SET rub = rub - $1 WHERE email = $2", request.Amount, email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not withdraw: " + err.Error()})
			return
		}
	case "usd":
		result, err = db.Exec("UPDATE users_wallet SET usd = usd - $1 WHERE email = $2", request.Amount, email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not withdraw: " + err.Error()})
			return
		}
	case "eur":
		result, err = db.Exec("UPDATE users_wallet SET eur = eur - $1 WHERE email = $2", request.Amount, email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "could not withdraw: " + err.Error()})
			return
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid currency"})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not update balance: " + err.Error()})
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "update failed, check if the user exists"})
		return
	}

	var rub, usd, eur float64
	err = db.QueryRow("SELECT rub, usd, eur FROM users_wallet WHERE email = $1", email).Scan(&rub, &usd, &eur)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "no data found for this user"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not get balance"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "withdraw successful", "new balance": gin.H{"rub": rub, "usd": usd, "eur": eur}})
}

func main() {
	initDB()
	defer db.Close() // Закрыть соединение с БД при завершении работы

	r := gin.Default()
	r.POST("/register", register)
	r.POST("/login", login)

	authRoutes := r.Group("/auth").Use(TokenAuthMiddleware)
	{
		authRoutes.GET("/profile", profile) // Пример защищенного маршрута
		authRoutes.GET("/balance", balance)
		authRoutes.POST("/deposit", deposit)
		authRoutes.POST("/withdraw", withdraw)
	}

	r.Run(":8080") // Запуск сервера на порту 8080
}

//curl -X POST http://localhost:8080/register -d '{"mail": "testuser2@gmail.com", "password": "password123fа"}' -H "Content-Type: application/json"
//curl -X POST http://localhost:8080/login -d '{"mail": "p@mail.com", "password": "p"}' -H "Content-Type: application/json"
//curl -H "Authorization: Bearer <token>" http://localhost:8080/auth/profile
//curl -H "Authorization: Bearer <token>" http://localhost:8080/auth/balance
//curl -X POST http://localhost:8080/auth/deposit \-H "Authorization: Bearer токен" -H "Content-Type: application/json" -d '{"amount": 100.0, "currency": "usd"}'
//curl -X POST http://localhost:8080/auth/withdraw \-H "Authorization: Bearer токен" -H "Content-Type: application/json" -d '{"amount": 100.0, "currency": "usd"}'
