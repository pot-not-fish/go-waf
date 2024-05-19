package dao

import (
	"fmt"
	"log"
	"os"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

type User struct {
	Username string
	Password string
}

// 连接数据库
func Init() {
	var err error

	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold: time.Microsecond,
			LogLevel:      logger.Info,
		},
	)

	username := "root" // 使用者名字 如root
	password := "123456"
	host := "127.0.0.1"
	port := 3306
	dbname := "test" // 数据库名字
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8&parseTime=True&loc=Local", username, password, host, port, dbname)

	DB, err = gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: newLogger, // 将SQL信息打印到终端
		DryRun: false,
	})
	if err != nil {
		panic(err)
	}
	DB.AutoMigrate(&User{})
}
