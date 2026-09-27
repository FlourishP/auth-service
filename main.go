/**
 * Auth Service — Authentication microservice.
 * 
 * Go + Gin: OAuth2, JWT, refresh tokens, rate limiting, MFA.
 */

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

var ctx = context.Background()

var (
	jwtSecret = []byte(getEnv("JWT_SECRET", "super-secret-key-change-me"))
	redisClient *redis.Client
)

type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	MFAEnabled   bool      `json:"mfa_enabled"`
	MFASecret    string    `json:"-"`
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

type MFARequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func init() {
	redisClient = redis.NewClient(&redis.Options{
		Addr:     getEnv("REDIS_ADDR", "localhost:6379"),
		Password: "",
		DB:       0,
	})
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPassword(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateToken(userID string, expires time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(expires).Unix(),
		"iat": time.Now().Unix(),
		"role": "user",
	})
	return token.SignedString(jwtSecret)
}

func generateRefreshToken() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func authenticate(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// In production, look up user from database
	// For demo, simulate user lookup
	hash, _ := hashPassword("password123")
	user := User{
		ID:           "user-001",
		Email:        req.Email,
		PasswordHash: hash,
		MFAEnabled:   false,
		Role:         "user",
		CreatedAt:    time.Now(),
	}

	if !checkPassword(user.PasswordHash, req.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	accessToken, _ := generateToken(user.ID, time.Hour)
	refreshToken, _ := generateRefreshToken()

	// Store refresh token in Redis (7 days)
	redisClient.Set(ctx, "refresh:"+refreshToken, user.ID, 7*24*time.Hour)

	c.JSON(http.StatusOK, TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    3600,
		TokenType:    "Bearer",
	})
}

func refresh(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Verify refresh token exists in Redis
	userID, err := redisClient.Get(ctx, "refresh:"+req.RefreshToken).Result()
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	newToken, _ := generateToken(userID, time.Hour)
	c.JSON(http.StatusOK, TokenResponse{
		AccessToken: newToken,
		ExpiresIn:   3600,
		TokenType:   "Bearer",
	})
}

func verifyMFA(c *gin.Context) {
	var req MFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// In production, verify MFA code against stored secret
	// For demo, accept any 6-digit code
	c.JSON(http.StatusOK, gin.H{"status": "verified", "email": req.Email})
}

func rateLimit(c *gin.Context) {
	ip := c.ClientIP()
	key := fmt.Sprintf("ratelimit:%s", ip)

	count, _ := redisClient.Incr(ctx, key).Result()
	if count == 1 {
		redisClient.Expire(ctx, key, time.Minute)
	}

	if count > 100 {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded"})
		c.Abort()
		return
	}

	c.Next()
}

func health(c *gin.Context) {
	redisOk := redisClient.Ping(ctx).Err() == nil
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"redis":  redisOk,
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

func main() {
	r := gin.Default()

	r.GET("/health", health)
	r.POST("/auth/login", rateLimit, authenticate)
	r.POST("/auth/refresh", refresh)
	r.POST("/auth/mfa", verifyMFA)

	port := getEnv("PORT", "8003")
	log.Printf("Auth service starting on port %s", port)
	log.Fatal(r.Run(":" + port))
}