package injection

import (
	"fmt"
	"regexp"
)

type CodeInjection struct{}

func (c *CodeInjection) Check(data string) error {
	re := regexp.MustCompile(`(os\.exec|exec\.Command|)`)
	if re.MatchString(data) {
		return fmt.Errorf("warning: risk go function")
	}

	return nil
}

type SQLInjection struct{}

func (c *SQLInjection) Check(data string) error {
	// 联合注入检测
	re := regexp.MustCompile(`(?i)union\s+select`)
	if re.MatchString(data) {
		return fmt.Errorf("warning: union select")
	}

	// sql危险函数绕过
	re = regexp.MustCompile(`(?i)\b(benchmark|concat_ws|group_concat|datadir|HEX|BIN|MID|SUBSTR|SUBSTRING|ASCII|PASSWORD|CAST|EXTRACT|DATABASE|USER|VERSION|CONCAT|SYSTEM_USER|SESSION_USER|CURRENT_USER|LOAD_FILE|INFOMATION_SCHEMA)\b`)
	if re.MatchString(data) {
		return fmt.Errorf("warning: risk function")
	}

	// 分号后注入攻击
	re = regexp.MustCompile(`(?i)\b(SELECT|INSERT|UPDATE|DELETE|UNION|DROP|TRUNCATE|ALTER|CREATE|GRANT|REVOKE)\b`)
	if re.MatchString(data) {
		return fmt.Errorf("warning: risk sql")
	}

	// 注释绕过
	re = regexp.MustCompile(`\b[a-zA-Z]*(<>|/\*\*/)[a-zA-Z]*\b`)
	if re.MatchString(data) {
		return fmt.Errorf("warning: exist annotation")
	}

	return nil
}

type XSSInjection struct{}

func (c *XSSInjection) Check(data string) error {
	// 检测危险html标签
	re := regexp.MustCompile(`(?i)<(?:script|img|a|input|body|svg|iframe).*>`)
	if re.MatchString(data) {
		return fmt.Errorf("warning: risk html lable")
	}

	// 检测危险js事件
	re = regexp.MustCompile(`(?i)\b(?:onmouseover|onclick|onfocus|onblur|onload|oneerror)\b`)
	if re.MatchString(data) {
		return fmt.Errorf("warning: risk event")
	}

	// 检测注释绕过
	re = regexp.MustCompile(`(/\*.*\*/|<!--.*-->|//)`)
	if re.MatchString(data) {
		return fmt.Errorf("warning: risk annotation")
	}

	// 检测绕过编码，包括unicode编码，html实体编码，url编码
	re = regexp.MustCompile(`(\\u[0-9a-fA-F]{4}|&#[0-9a-zA-Z]+|%[0-9a-fA-F]{2})`)
	if re.MatchString(data) {
		return fmt.Errorf("warning: risk encoding")
	}

	return nil
}

type CommandInjection struct{}

func (c *CommandInjection) Check(data string) error {
	// 连接符绕过
	re := regexp.MustCompile("(\\||&|&&|\\|\\||;|`.+`|\n)")
	if re.MatchString(data) {
		return fmt.Errorf("warning: risk connector")
	}

	// linux命令更换绕过
	re = regexp.MustCompile("(rm|cp|mv|chown|chmod|wget|curl|ssh|su|sudo|nc|telnet|netcat|bash|sh|python|perl|ruby|node|java|tar|unzip|find|locate|echo)")
	if re.MatchString(data) {
		return fmt.Errorf("warning: risk command")
	}

	// 编码绕过检测，包括空格特殊编码，$的变量绕过
	re = regexp.MustCompile(`(<|<>|%20\(space\)|%09\(tab\)|\$IFS\$9|\$\{IFS\}|\$IFS|\$\(.+\)|\$\{.+\})`)
	if re.MatchString(data) {
		return fmt.Errorf("warning: risk encoding")
	}

	return nil
}
