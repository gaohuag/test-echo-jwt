package main

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"net/http"
	"time"
)

func login(c echo.Context) error {

	info := struct {
		UserName string `json:"username"`
		PassWord string `json:"password"`
	}{}
	err := c.Bind(&info)
	if err != nil {
		panic(err)
	}
	username := info.UserName
	password := info.PassWord
	if username == "jon" && password == "shhh!" {
		// Set custom claims
		claims := &jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 72).Unix(),
			Id:        username,
		}
		// Create token with claims
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		// Generate encoded token and send it as response.
		t, err := token.SignedString([]byte("secret"))
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, echo.Map{
			"token": t,
		})
	}
	return echo.ErrUnauthorized
}
func accessible(c echo.Context) error {
	return c.String(http.StatusOK, "Accessible")
}
func restricted(c echo.Context) error {
	name := c.Get("people_id").(string)
	return c.String(http.StatusOK, "Welcome "+name+"!")
}
func main() {
	e := echo.New()
	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	// Login route
	e.POST("/login", login)
	// Unauthenticated route
	e.GET("/", accessible)
	// Restricted group
	r := e.Group("/restricted")
	// Configure middleware with the custom claims type
	config := middleware.JWTConfig{
		Claims:     &jwt.StandardClaims{},
		SigningKey: []byte("secret"),
		SuccessHandler: func(c echo.Context) {
			user := c.Get("user").(*jwt.Token)
			claims := user.Claims.(*jwt.StandardClaims)
			c.Set("people_id", claims.Id)
		},
	}
	r.Use(middleware.JWTWithConfig(config))
	r.GET("", restricted)
	e.Logger.Fatal(e.Start(":8080"))
}
