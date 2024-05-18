package handler

import (
	"bytes"
	"fmt"
	"go-waf/pkg/dao"
	"io"
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

func Response(c *gin.Context) {
	if _, ok := c.Get("isValid"); !ok {
		c.JSON(http.StatusOK, gin.H{"code": 0, "msg": "OK"})
	}
}

type UserReq struct {
	Username string `form:"username" json:"username" xml:"username"`
	Password string `form:"password" json:"password" xml:"password"`
}

func SQL(c *gin.Context) {
	if _, ok := c.Get("isValid"); ok {
		return
	}

	var (
		err     error
		userReq UserReq
	)
	if err := c.ShouldBind(&userReq); err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 1, "msg": "invalid paramenter"})
		return
	}

	// 查询用户名是否正确
	var (
		user []map[string]interface{} // 存在注入风险，直接将所有请求获取的数据返回给前端
	)
	if err = dao.DB.Model(&dao.User{}).Where(fmt.Sprintf("username = '%v' AND password = '%v'", userReq.Username, userReq.Password)).Find(&user).Error; err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 1, "msg": err.Error()})
	}

	c.JSON(http.StatusOK, gin.H{"code": 0, "msg": "ok", "data": user})
}

var (
	load = ""
)

func XSS(c *gin.Context) {
	if _, ok := c.Get("isValid"); ok {
		return
	}

	data := c.PostForm("data")

	if data != "" {
		load = data
	}

	c.HTML(http.StatusOK, "hello.tmpl", gin.H{"title": load})
}

func Command(c *gin.Context) {
	if _, ok := c.Get("isValid"); ok {
		return
	}

	data := c.Request.Header.Get("data")

	cmd := exec.Command("cmd.exe", "/c", data)
	out, err := cmd.CombinedOutput()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 1, "msg": err.Error()})
		return
	}

	reader := transform.NewReader(bytes.NewReader(out), simplifiedchinese.GBK.NewDecoder())
	d, err := io.ReadAll(reader)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 1, "msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 1, "msg": "OK", "data": string(d)})
}
