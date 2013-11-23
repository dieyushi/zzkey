package main

import (
	"bufio"
	"code.google.com/p/go.crypto/ssh/terminal"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"os/exec"
	"os/user"
	"path"
	"strings"
	"time"
)

var VERSION string = "zzkey 0.1-dev"
var cu, _ = user.Current()
var KEY_ROOT string = path.Join(cu.HomeDir, ".zzkey")
var KEY_ROOT_DB string = path.Join(cu.HomeDir, ".zzkey", "db")
var KEY_ROOT_PASSWD string = path.Join(cu.HomeDir, ".zzkey", "passwd")

var password string

type Info struct {
	Name        string
	Passwd      string
	Description string
}

var BLUECOLOR = "\033[94m"
var COLOREND = "\033[0m"

var lastActiveTime int64

func showAllRecord() {
	_, err := os.Stat(KEY_ROOT_DB)
	if err != nil {
		fmt.Fprintf(os.Stderr, "database not found!\nyou can run 'clean' or 'set' a record to initial the database\n")
		return
	}

	buf, _ := ioutil.ReadFile(KEY_ROOT_DB)
	data := strings.Split(decryptFromBase64(string(buf), password), "\n")

	var i int
	for _, n := range data {
		var m Info
		json.Unmarshal([]byte(n), &m)
		if m.Name != "" {
			if i%4 == 0 && i != 0 {
				fmt.Printf("\n")
			}
			fmt.Printf("%-15s  ", m.Name)
			i++
		}
	}
	fmt.Printf("\ntotal %d\n", i)
	return
}

func getRecord(p string) (e error) {
	_, err := os.Stat(KEY_ROOT_DB)
	if err != nil {
		e = errors.New("database not found!\nyou can run 'clean' or 'set' a record to initial the database")
		return
	}

	buf, _ := ioutil.ReadFile(KEY_ROOT_DB)
	data := strings.Split(decryptFromBase64(string(buf), password), "\n")

	for _, n := range data {
		var m Info
		json.Unmarshal([]byte(n), &m)
		if m.Name == p {
			fmt.Printf("[-] Name:        %s\n", p)
			fmt.Printf("[-] Password:    %s\n", m.Passwd)
			fmt.Printf("[-] Description: %s\n", m.Description)
			e = nil
			return
		}
	}
	e = errors.New("record not found!")
	return
}

func getRecordToClipboard(p string) (e error) {
	_, err := os.Stat(KEY_ROOT_DB)
	if err != nil {
		e = errors.New("database not found!\nyou can run 'clean' or 'set' a record to initial the database")
		return
	}

	buf, _ := ioutil.ReadFile(KEY_ROOT_DB)
	data := strings.Split(decryptFromBase64(string(buf), password), "\n")

	found := make(map[string]string)
	for _, n := range data {
		var m Info
		json.Unmarshal([]byte(n), &m)
		if strings.Contains(m.Name, p) {
			found[m.Name] = m.Passwd
		}
	}

	if len(found) == 1 {
		for _, password := range found {
			err := setClipboard(password)
			if err != nil {
				e = errors.New("copy record to clipboard error")
				return
			}
			fmt.Println("password copied to the clipboard, existing for 30s.")
		}
	} else if len(found) == 0 {
		e = errors.New("record not found!")
	} else if len(found) > 1 {
		fmt.Fprintf(os.Stderr, "more than one record match %s\n", p)
		for name, _ := range found {
			fmt.Printf("[-] %s\n", name)
		}
	}
	return
}

func setClipboard(password string) (e error) {
	cmd1 := exec.Command("echo", "-n", password)
	cmd2 := exec.Command("xsel", "-b")
	cmd2.Stdin, _ = cmd1.StdoutPipe()
	cmd2.Stdout = os.Stdout

	cmd2.Start()
	cmd1.Run()
	e = cmd2.Wait()
	return
}

func setRecord(p string) {
	if e := getRecord(p); e == nil {
		fmt.Fprintf(os.Stderr, "record already exists\n")
		return
	}

	fmt.Printf("use random password ?\n[y/n] ")
	ra := bufio.NewReader(os.Stdin)
	uinput, _, _ := ra.ReadLine()
	var setpass string
	if string(uinput) == "y" {
		pass := randomPasswd(16)
		fmt.Printf("random password : %s\n", pass)
		setpass = pass
	} else {
		fmt.Printf("%s's Password :", p)
		pass, _ := terminal.ReadPassword(int(os.Stdin.Fd()))
		fmt.Printf("\n")

		fmt.Printf("Repeat Password :")
		passagain, _ := terminal.ReadPassword(int(os.Stdin.Fd()))
		fmt.Printf("\n")

		if string(pass) != string(passagain) {
			fmt.Fprintf(os.Stderr, "not match\n")
			return
		}
		setpass = string(pass)
	}

	fmt.Printf("%s's Description : ", p)
	r := bufio.NewReader(os.Stdin)
	input, _, _ := r.ReadLine()
	description := string(input)

	i := Info{p, string(setpass), string(description)}
	j, _ := json.Marshal(i)
	j = append(j, '\n')

	content := string(j)
	_, err := os.Stat(KEY_ROOT_DB)
	if err == nil {
		buf, _ := ioutil.ReadFile(KEY_ROOT_DB)
		content = decryptFromBase64(string(buf), password)
		content += string(j)
	}
	k := encryptToBase64(content, password)
	if e := ioutil.WriteFile(KEY_ROOT_DB, []byte(k), 0600); e != nil {
		fmt.Fprintf(os.Stderr, "add record failed")
	}

	fmt.Printf("record add to the database\n")
}

func unsetRecord(p string) {
	_, err := os.Stat(KEY_ROOT_DB)
	if err != nil {
		fmt.Fprintf(os.Stderr, "database not found!\nyou can run 'clean' or 'set' a record to initial the database\n")
		return
	}

	buf, _ := ioutil.ReadFile(KEY_ROOT_DB)
	data := strings.Split(decryptFromBase64(string(buf), password), "\n")
	unsetID := -1
	for i, n := range data {
		var m Info
		json.Unmarshal([]byte(n), &m)
		if m.Name == p {
			unsetID = i
		}
	}

	if unsetID == -1 {
		fmt.Fprintf(os.Stderr, "record no found\n")
		return
	}

	var content string
	for i, str := range data {
		if i != unsetID && str != "" {
			content = content + str + "\n"
		}
	}

	k := encryptToBase64(content, password)
	if e := ioutil.WriteFile(KEY_ROOT_DB, []byte(k), 0600); e != nil {
		fmt.Fprintf(os.Stderr, "unset record failed")
	}

	fmt.Printf("record unseted\n")
}

func resetRecord(p string) {
	unsetRecord(p)
	setRecord(p)
}

func cleanRecords() {
	fmt.Printf("this operation will erase all your data,\nstill go on?\n[y/n] ")
	r := bufio.NewReader(os.Stdin)
	input, _, _ := r.ReadLine()
	if string(input) != "y" {
		return
	}

	if e := ioutil.WriteFile(KEY_ROOT_DB, []byte(""), 0600); e != nil {
		fmt.Fprintf(os.Stderr, "clean database failed\n")
	} else {
		fmt.Printf("database cleaned\n")
	}
}

func searchRecord(p string) {
	_, err := os.Stat(KEY_ROOT_DB)
	if err != nil {
		fmt.Fprintf(os.Stderr, "database not found!\nyou can run 'clean' or 'set' a record to initial the database\n")
		return
	}

	buf, _ := ioutil.ReadFile(KEY_ROOT_DB)
	data := strings.Split(decryptFromBase64(string(buf), password), "\n")

	var found int
	for _, n := range data {
		var m Info
		json.Unmarshal([]byte(n), &m)
		if strings.Contains(m.Name, p) || strings.Contains(m.Description, p) {
			fmt.Printf("[-] %s\n", m.Name)
			found++
		}
	}
	if found == 0 {
		fmt.Fprintf(os.Stderr, "no suitable record found!\n")
	} else {
		fmt.Printf("%d records found!\n", found)
	}
	return
}

func showHelp() {
	fmt.Printf("Usage:  [option] [...params]\n")
	fmt.Println("Options:")
	fmt.Println("\tset\t\t set a new record")
	fmt.Println("\tsete\t\t set a new record and exit")
	fmt.Println("\tunset\t\t delete an existing record")
	fmt.Println("\treset\t\t reset an existing record")
	fmt.Println("\tget\t\t copy record password to clipboard, get is optional")
	fmt.Println("\tgete\t\t copy record password to clipboard and exit")
	fmt.Println("\tsee\t\t show an existing record")
	fmt.Println("\tsearch\t\t search exist record")
	fmt.Println("\tversion\t\t show version string")
	fmt.Println("\tshowall\t\t show all record's name")
	fmt.Println("\tclean\t\t clean the database")
	fmt.Println("\tpasswd\t\t change zzkey passwd")
	fmt.Println("\texit\t\t exit zzkey")
	fmt.Println("\thelp\t\t show this message")
}

func randomPasswd(length int) string {
	alphabet := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	alphabetLength := int64(len(alphabet))
	randomPassword := make([]byte, length)

	for i := 0; i < length; i++ {
		r, _ := rand.Int(rand.Reader, big.NewInt(alphabetLength))
		randomPassword[i] = alphabet[r.Int64()]
	}
	return string(randomPassword)
}

func checkXsel() bool {
	_, err := exec.Command("xsel", "--version").Output()
	if err != nil {
		fmt.Printf("zzkey couldn't find xsel in PATH, please install xsel first.\n")
		return false
	}
	return true
}

func checkKeyRoot() {
	_, err := os.Stat(KEY_ROOT)
	if err != nil {
		e := os.Mkdir(KEY_ROOT, 0700)
		if e != nil {
			fmt.Printf("%s\n", e.Error())
		}
	}
}

func checkKeyPasswd() bool {
	_, err := os.Stat(KEY_ROOT_PASSWD)
	if err != nil {
		return false
	}
	return true
}

func changePasswd() {
	fmt.Printf("current password :")
	currentPass, _ := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Printf("\n")
	if string(currentPass) != password {
		fmt.Fprintf(os.Stderr, "password error\n")
		return
	}
	createPasswd()
	buf, _ := ioutil.ReadFile(KEY_ROOT_DB)
	data := decryptFromBase64(string(buf), string(currentPass))

	k := encryptToBase64(data, password)
	ioutil.WriteFile(KEY_ROOT_DB, []byte(k), 0600)
	fmt.Printf("password changed\n")
}

func createPasswd() {
	_, err := os.Stat(KEY_ROOT_PASSWD)
	if err != nil {
		fmt.Printf("This is your first time working with zzkey\n")
		fmt.Printf("Please input a password to protect your infomation\n")
	}

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

	password = string(buf)
	buf2 := string(buf) + "--salt add by zzkey--"
	h := sha1.New()
	io.WriteString(h, buf2)
	buf2 = fmt.Sprintf("%x", h.Sum(nil))
	ioutil.WriteFile(KEY_ROOT_PASSWD, []byte(buf2), 0600)
	fmt.Println("Password has been set,Having Fun With zzkey!")
}

func verifyPasswd() (p string, e error) {
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
		password = string(pass)
		return
	}
	p, e = "", errors.New("Wrong Password")
	return
}

func encryptToBase64(content string, k string) string {
	var commonIV = []byte{0x1f, 0x2c, 0x49, 0xea, 0xb5, 0xf3, 0x47, 0x2e, 0xa8, 0x71, 0x0a, 0xc0, 0x4e, 0x5d, 0x83, 0x19}
	plaintext := []byte(content)
	key_salt := "3z0RlwtvIOdlC8aAwIaCbX0D"
	var key_text string
	if len(k) < 24 {
		key_text = k + key_salt[len(k):]
	}
	if len(k) > 24 {
		key_text = k[:24]
	}

	c, err := aes.NewCipher([]byte(key_text))
	if err != nil {
		fmt.Printf("Error: NewCipher(%d bytes) = %s", len(key_text), err)
		os.Exit(-1)
	}

	cfb := cipher.NewCFBEncrypter(c, commonIV)
	ciphertext := make([]byte, len(plaintext))
	cfb.XORKeyStream(ciphertext, plaintext)

	base64Text := base64.StdEncoding.EncodeToString(ciphertext)
	return string(base64Text)
}

func decryptFromBase64(content string, k string) string {
	ciphertext, _ := base64.StdEncoding.DecodeString(content)
	var commonIV = []byte{0x1f, 0x2c, 0x49, 0xea, 0xb5, 0xf3, 0x47, 0x2e, 0xa8, 0x71, 0x0a, 0xc0, 0x4e, 0x5d, 0x83, 0x19}

	key_salt := "3z0RlwtvIOdlC8aAwIaCbX0D"
	var key_text string
	if len(k) < 24 {
		key_text = k + key_salt[len(k):]
	}
	if len(k) > 24 {
		key_text = k[:24]
	}

	c, err := aes.NewCipher([]byte(key_text))
	if err != nil {
		fmt.Printf("Error: NewCipher(%d bytes) = %s", len(key_text), err)
		os.Exit(-1)
	}

	cfb := cipher.NewCFBDecrypter(c, commonIV)
	plaintext := make([]byte, len(ciphertext))
	cfb.XORKeyStream(plaintext, ciphertext)
	return string(plaintext)
}

func checkLastActive() {
	for {
		if time.Now().Unix()-lastActiveTime > 20 {
			break
		} else {
			time.Sleep(1 * time.Second)
		}
	}
	setClipboard("")
	fmt.Fprintf(os.Stderr, "no input within 20s, exiting\n")
	os.Exit(0)
}

func zzkeyShell() {
	prompt := BLUECOLOR + "zzkey> " + COLOREND
	lastActiveTime = time.Now().Unix()
	go checkLastActive()
	for {
		command := ReadLine(&prompt)
		lastActiveTime = time.Now().Unix()

		switch *command {
		case "exit":
			fmt.Println("Bye")
			return
		case "help":
			showHelp()
		case "showall":
			showAllRecord()
		case "version":
			fmt.Println(VERSION)
		case "clean":
			cleanRecords()
		case "passwd":
			changePasswd()
		default:
			commandlist := strings.Fields(*command)
			if len(commandlist) == 1 {
				if e := getRecordToClipboard(commandlist[0]); e != nil {
					fmt.Fprintf(os.Stderr, "unexpect parameter\n")
				}
			} else if len(commandlist) != 2 {
				fmt.Fprintln(os.Stderr, "parse parameter error")
			} else {
				switch commandlist[0] {
				case "get":
					if e := getRecordToClipboard(commandlist[1]); e != nil {
						fmt.Fprintf(os.Stderr, "%s\n", e.Error())
					}
				case "gete":
					if e := getRecordToClipboard(commandlist[1]); e != nil {
						fmt.Fprintf(os.Stderr, "%s\n", e.Error())
					}
					return
				case "see":
					if e := getRecord(commandlist[1]); e != nil {
						fmt.Fprintf(os.Stderr, "%s\n", e.Error())
					}
				case "set":
					setRecord(commandlist[1])
				case "sete":
					setRecord(commandlist[1])
					return
				case "unset":
					unsetRecord(commandlist[1])
				case "reset":
					resetRecord(commandlist[1])
				case "search":
					searchRecord(commandlist[1])
				default:
					fmt.Fprintf(os.Stderr, "unexpect parameter\n")
				}
			}
		}
		AddHistory(*command)
	}
}

func main() {
	if !checkXsel() {
		return
	}
	checkKeyRoot()
	if !checkKeyPasswd() {
		createPasswd()
		return
	}

	if _, e := verifyPasswd(); e != nil {
		fmt.Printf("%s\n", e.Error())
		return
	}
	zzkeyShell()
	setClipboard("")
	return
}
