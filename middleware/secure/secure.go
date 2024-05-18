package secure

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	FP *os.File
)

func Init() {
	var err error

	FP, err = os.OpenFile("app.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		panic(err)
	}
	log.SetOutput(FP)
}

func Protect(path string, guard Guard, params ...string) func(c *gin.Context) {
	return func(c *gin.Context) {
		switch path {
		case "cookie":
			cookieParse(c, guard, params...)
		case "header":
			headerParse(c, guard, params...)
		case "body":
			bodyParse(c, guard, params...)
		case "query":
			queryParse(c, guard, params...)
		default:
			c.JSON(http.StatusBadRequest, nil)
		}
	}
}

type Guard interface {
	Check(data string) error
}

func cookieParse(c *gin.Context, guard Guard, params ...string) {
	for i := range params {
		data, err := c.Cookie(params[i])
		if err != nil {
			c.Set("isValid", false)
			log.Printf("%s - [%s] \"%s %s %s",
				c.ClientIP(),
				time.Now().UTC().Format(time.RFC1123),
				c.Request.Method,
				c.Request.URL.Path,
				err.Error(),
			)
			c.JSON(http.StatusBadRequest, nil)
			return
		}
		if err = guard.Check(data); err != nil {
			c.Set("isValid", false)
			c.JSON(http.StatusForbidden, gin.H{"code": 1, "msg": err.Error()})
			log.Printf("%s - [%s] \"%s %s %s",
				c.ClientIP(),
				time.Now().UTC().Format(time.RFC1123),
				c.Request.Method,
				c.Request.URL.Path,
				err.Error(),
			)
			return
		}
	}
	c.Next()
}

func bodyParse(c *gin.Context, guard Guard, params ...string) {
	for i := range params {
		data := c.PostForm(params[i])
		if err := guard.Check(data); err != nil {
			c.Set("isValid", false)
			c.JSON(http.StatusForbidden, gin.H{"code": 1, "msg": err.Error()})
			log.Printf("%s - [%s] \"%s %s %s",
				c.ClientIP(),
				time.Now().UTC().Format(time.RFC1123),
				c.Request.Method,
				c.Request.URL.Path,
				err.Error(),
			)
			return
		}
	}
	c.Next()
}

func queryParse(c *gin.Context, guard Guard, params ...string) {
	for i := range params {
		data := c.Query(params[i])
		fmt.Println(data)
		if err := guard.Check(data); err != nil {
			c.Set("isValid", false)
			c.JSON(http.StatusForbidden, gin.H{"code": 1, "msg": err.Error()})
			log.Printf("%s - [%s] \"%s %s %s",
				c.ClientIP(),
				time.Now().UTC().Format(time.RFC1123),
				c.Request.Method,
				c.Request.URL.Path,
				err.Error(),
			)
			return
		}
	}
	c.Next()
}

func headerParse(c *gin.Context, guard Guard, params ...string) {
	for i := range params {
		data := c.Request.Header.Get(params[i])
		if data == "" {
			c.Set("isValid", false)
			c.JSON(http.StatusBadRequest, nil)
			return
		}
		if err := guard.Check(data); err != nil {
			c.Set("isValid", false)
			c.JSON(http.StatusForbidden, gin.H{"code": 1, "msg": err.Error()})
			log.Printf("%s - [%s] \"%s %s %s",
				c.ClientIP(),
				time.Now().UTC().Format(time.RFC1123),
				c.Request.Method,
				c.Request.URL.Path,
				err.Error(),
			)
			return
		}
	}
	c.Next()
}
