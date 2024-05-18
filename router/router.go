package router

import (
	"go-waf/handler"
	"go-waf/middleware/secure"
	"go-waf/pkg/injection"

	"github.com/gin-gonic/gin"
)

func Register(r *gin.Engine) {
	v1 := r.Group("protect")
	{
		v1.GET("/sql", secure.Protect("query", &injection.SQLInjection{}, "username", "password"), handler.SQL)
		v1.POST("/xss", secure.Protect("body", &injection.XSSInjection{}, "data"), handler.XSS)
		v1.POST("/command", secure.Protect("header", &injection.CommandInjection{}, "data"), handler.Command)
		v1.POST("/code", secure.Protect("cookie", &injection.CodeInjection{}, "data"), handler.Response)
	}

	// v1 := r.Group("protect")
	// {
	// 	v1.GET("/sql", handler.SQL)
	// 	v1.POST("/xss", handler.XSS)
	// 	v1.POST("/command", handler.Command)
	// 	v1.POST("/code", secure.Protect("cookie", &injection.CodeInjection{}, "data"), handler.Response)
	// }
}
