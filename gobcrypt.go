package gobcrypt

import "golang.org/x/crypto/bcrypt"

// It takes the password you want to hash.
// Note: it uses default cost.
func HashPassword(password string) string {
	hashedPswd, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	if err != nil {
		panic(err)
	}

	return string(hashedPswd)
}

// It takes the already hashed password first then the password you want to compare it with.
func VerifyPassword(hashedPassword string, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))

	if err != nil {
		panic(err)
	}

	return err == nil
}
