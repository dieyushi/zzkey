package main

import (
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"strings"
	"zzkey/terminal"
)

var cu, _ = user.Current()
var KEY_ROOT string = path.Join(cu.HomeDir, ".zzkey")
var KEY_ROOT_DB string = path.Join(cu.HomeDir, ".zzkey", "db")
var KEY_ROOT_PASSWD string = path.Join(cu.HomeDir, ".zzkey", "passwd")

type Info struct {
	Name   string
	Passwd string
}

func IsKeyRootExist() {
	_, err := os.Stat(KEY_ROOT)
	if err != nil {
		fmt.Printf("%s\n", err.Error())
		e := os.Mkdir(KEY_ROOT, 0700)
		if e != nil {
			fmt.Printf("%s\n", e.Error())
		}
	}
}

func IsKeyPasswdExist() bool {
	_, err := os.Stat(KEY_ROOT_PASSWD)
	if err != nil {
		fmt.Printf("%s\n", err.Error())
		return false
	}
	return true
}

func CreatePasswd() {
	fmt.Printf("Please input a password to protect your infomation\n")
	fmt.Printf("Password :")
	buf, _ := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Printf("\n")
	fmt.Printf("Repeat :")
	buf1, _ := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Printf("\n")
	if string(buf) != string(buf1) {
		fmt.Printf("not match\n")
		return
	}
	/*fmt.Println(buf)*/
	buf2 := string(buf) + "--salt add by zzkey--"
	h := sha1.New()
	io.WriteString(h, buf2)
	buf2 = fmt.Sprintf("%x", h.Sum(nil))
	ioutil.WriteFile(KEY_ROOT_PASSWD, []byte(buf2), 0600)
}

func VerifyPasswd() (p string, e error) {
	buf, _ := ioutil.ReadFile(KEY_ROOT_PASSWD)
	fmt.Printf("Password :")
	pass, _ := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Printf("\n")
	pass2 := string(pass) + "--salt add by zzkey--"
	h := sha1.New()
	io.WriteString(h, pass2)
	pass2 = fmt.Sprintf("%x", h.Sum(nil))
	if pass2 == string(buf) {
		p, e = pass2, nil
		return
	}
	p, e = "", errors.New("Wrong Password")
	return
}

func ParseParameter() (p1 string, p2 string, e error) {
	if len(os.Args) == 3 {
		p1 = os.Args[1]
		p2 = os.Args[2]
		e = nil
	} else {
		p1 = ""
		p2 = ""
		e = errors.New("parse parameter error")
	}
	return
}

func HandleParameter(p1, p2 string) {
	switch p1 {
	case "get":
		s, e := GetSomething(p2)
		if e != nil {
			fmt.Printf("%s\n", e.Error())
		}
		if s != "" {
			fmt.Printf("%s\n", s)
		}
	case "push":
		PushSomthing(p2)
	default:
		fmt.Fprintf(os.Stderr, "unexpect parameter\n")
	}
}

func GetSomething(p2 string) (s string, e error) {
	_, err := os.Stat(KEY_ROOT_DB)
	if err != nil {
		e = errors.New("DB file not found")
		s = ""
		return
	}

	buf, _ := ioutil.ReadFile(KEY_ROOT_DB)
	s = string(buf)
	data := strings.Fields(s)
	s = ""
	for _, n := range data {
		var m Info
		json.Unmarshal([]byte(n), &m)
		if m.Name == p2 {
			s = m.Passwd
			e = nil
			return
		}
	}
	e = errors.New("not found")
	return
}

func PushSomthing(p2 string) {
	/*_,err := os.Stat(KEY_ROOT_DB)*/
	/*if err != nil {*/
	/*ioutil.WriteFile(KEY_ROOT_DB,[]byte(p2),0600)*/
	/*}*/
	/*ioutil.WriteFile(KEY_ROOT_DB,[]byte(p2),0600)*/
	/*fmt.Printf("pushsomthing %s\n",p2)*/
	if _, e := GetSomething(p2); e == nil {
		fmt.Printf("Record exisits\n")
		return
	}
	fmt.Printf(p2 + "'s Password :")
	pass, _ := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Printf("\n")
	i := Info{p2, string(pass)}
	j, _ := json.Marshal(i)
	/*j = append(j,j)*/
	f, e := os.OpenFile(KEY_ROOT_DB, os.O_APPEND|os.O_RDWR|os.O_CREATE, 0600)
	if e != nil {
		fmt.Printf("%s\n", e.Error())
	}
	j = append(j, '\n')
	num, e := f.Write(j)
	if e != nil {
		fmt.Printf("%d %s\n", num, e.Error())
	}
	fmt.Printf("data append to the database\n")
}

func main() {
	p1, p2, e := ParseParameter()
	if e != nil {
		fmt.Printf("%s\n", e.Error())
		return
	}
	/*fmt.Println(p1,p2)*/
	IsKeyRootExist()
	createpass := IsKeyPasswdExist()
	if createpass == false {
		CreatePasswd()
	}
	if _, e := VerifyPasswd(); e != nil {
		fmt.Printf("%s\n", e.Error())
		return
	}
	HandleParameter(p1, p2)
}
