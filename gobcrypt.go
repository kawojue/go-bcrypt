// Package gobcrypt provides password hashing and comparison using golang.org/x/crypto/bcrypt.
package gobcrypt

import "golang.org/x/crypto/bcrypt"

// HashPassword generates a bcrypt hash for the given password using the default cost.
// It returns the hashed password as a string.
func HashPassword(password string) string {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return string(hashedPassword)
}

// CompareHashAndPassword compares a hashed password with a plaintext password.
// It takes the already hashed password first, followed by the plaintext password.
// It returns true if the passwords match, otherwise false.
func CompareHashAndPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// GenerateFromPassword is a wrapper for bcrypt.GenerateFromPassword with a custom cost.
// It allows you to specify a cost for password hashing.
// It returns the hashed password as a string.
func GenerateFromPassword(password string, cost int) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// Cost returns the cost used in the provided hashed password.
// It can be used to check the cost of an existing hash.
func Cost(hashedPassword string) (int, error) {
	cost, err := bcrypt.Cost([]byte(hashedPassword))
	return cost, err
}
