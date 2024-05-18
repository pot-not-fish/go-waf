package main

import (
	"go-waf/middleware/secure"
	"go-waf/pkg/dao"
	"go-waf/router"

	"github.com/gin-gonic/gin"
)

func main() {
	dao.Init()
	secure.Init()

	r := gin.Default()

	r.LoadHTMLGlob("./templates/*")

	router.Register(r)

	r.Run("127.0.0.1:8080")
}
