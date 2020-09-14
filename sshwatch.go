package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	assetfs "github.com/elazarl/go-bindata-assetfs"
	"golang.org/x/crypto/ssh"
)

type sliceData struct {
	Stamps  int64
	sshData map[string]string
}

var (
	httpserver  *string
	infoContain []sliceData
)

func init() {
	httpserver = flag.String("httpserver", "0.0.0.0:888", "httpserver addr")
}

func main() {
	flag.Parse()
	cliConf := new(ClientConfig)
	cliConf.createClient("10.100.123.246", 2024, "linuxadmin", "sonus")
	go sshSession(cliConf.Client)
	http_server_run(*httpserver)
}

func transTime(format string) int64 {
	format = strings.Replace(format, "T", " ", 1)
	format = format + ":00"
	loc, _ := time.LoadLocation("Local")
	timestamp, err := time.ParseInLocation("2006-01-02 15:04:05", format, loc)
	if err == nil {
		return timestamp.Unix()
	} else {
		return 0
	}
}
func http_server_run(httpserver string) {
	fs := assetfs.AssetFS{
		Asset:     Asset,
		AssetDir:  AssetDir,
		AssetInfo: AssetInfo,
	}
	http.Handle("/", http.FileServer(&fs))
	http.HandleFunc("/getinfo", func(w http.ResponseWriter, r *http.Request) {
		var responseInfo map[string]interface{}
		responseInfo = make(map[string]interface{})
		var datas []interface{}

		s, _ := ioutil.ReadAll(r.Body)
		var req map[string]interface{}
		err := json.Unmarshal(s, &req)
		if err == nil && req["startTime"] != nil && req["endTime"] != nil && len(req["startTime"].(string)) > 0 && len(req["endTime"].(string)) > 0 {
			startStamp := transTime(req["startTime"].(string))
			endStamp := transTime(req["endTime"].(string))

			interval := infoContain[1].Stamps - infoContain[0].Stamps
			startPos := (startStamp - infoContain[0].Stamps) / interval
			endPos := (endStamp - infoContain[0].Stamps) / interval
			if startPos < 0 {
				startPos = 0
			}
			if endPos > int64(len(infoContain)) {
				endPos = int64(len(infoContain))
			}
			if int(startPos) > len(infoContain)-1 {
				startPos = int64(len(infoContain)) - 1
			}

			if int(endPos) > len(infoContain)-1 {
				endPos = int64(len(infoContain)) - 1
			}

			for index := startPos; index > 0; index-- {
				startPos = index
				if infoContain[index].Stamps < startStamp {
					startStamp = index
					break
				}
			}
			for index := endPos; index < int64(len(infoContain)); index++ {
				endPos = index
				if infoContain[index].Stamps > endStamp {
					endPos = index
					break
				}
			}
			log.Println("start end time ", req["startTime"].(string), startStamp, req["endTime"].(string), endStamp)
			for _, info := range infoContain[startPos:endPos] {
				if startStamp < info.Stamps && info.Stamps < endStamp {
					datas = append(datas, info.sshData)
				}
			}
		} else {
			var start_pos int
			lens := len(infoContain)
			if lens > 100 {
				start_pos = lens - 100
			} else {
				start_pos = 0
			}
			for i := start_pos; i < lens; i++ {
				datas = append(datas, infoContain[i].sshData)
			}
		}
		responseInfo["data"] = datas
		responseInfo["result"] = "success"
		datasStr, err := json.Marshal(responseInfo)
		if err != nil {
			fmt.Fprintf(w, "{\"result\":\"failed\"}")
		} else {
			log.Println("===>", string(datasStr))
			fmt.Fprintf(w, string(datasStr))
		}
	})
	http.ListenAndServe(httpserver, nil)
}

type ClientConfig struct {
	Host     string
	Port     int64
	Username string
	Password string
	Client   *ssh.Client
}

func (cliConf *ClientConfig) createClient(host string, port int64, username, password string) {
	var (
		client *ssh.Client
		err    error
	)
	cliConf.Host = host
	cliConf.Port = port
	cliConf.Username = username
	cliConf.Password = password
	cliConf.Port = port
	config := ssh.ClientConfig{
		User: cliConf.Username,
		Auth: []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Timeout: 10 * time.Second,
	}
	addr := fmt.Sprintf("%s:%d", cliConf.Host, cliConf.Port)

	if client, err = ssh.Dial("tcp", addr, &config); err != nil {
		log.Fatalln(err)
	}
	cliConf.Client = client
}
func sshSession(client *ssh.Client) {
	var session *ssh.Session
	var err error
	if session, err = client.NewSession(); err != nil {
		log.Fatalln(err)
	}
	//session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	cmdReader, err := session.StdoutPipe()
	if err != nil {
		log.Println(err)
	}
	go praseStdout(cmdReader)

	session.Run("mpstat -P ALL 3")
}
func praseStdout(fd io.Reader) {
	var infoTmp sliceData
	var cpuinfo = make(map[string]string)
	var cpuCore int
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		msg := scanner.Text()
		if strings.Contains(msg, "all") {
			var timeFormat string
			infoTmp.Stamps = time.Now().Unix()
			timeFormat = time.Unix(infoTmp.Stamps, 0).Format("2006-01-02 15:04:05")
			cpuinfo["time"] = timeFormat
			infoTmp.sshData = cpuinfo
			_, ok := cpuinfo["cpu1"]
			if ok {
				infoContain = append(infoContain, infoTmp)
			}
			cpuCore = 0
			cpuinfo = make(map[string]string)
		} else {
			if !strings.Contains(msg, "Linux") && !strings.Contains(msg, "usr") {
				splitStr := strings.Split(msg, " ")
				//log.Println(splitStr)
				if len(splitStr) > 1 {
					//log.Println(">>>>>>>>>>>>>>>>>>>>>", cpuCore, splitStr[len(splitStr)-1])
					cpuinfo["cpu"+strconv.Itoa(cpuCore)] = splitStr[len(splitStr)-1]
					cpuCore = cpuCore + 1
				}
			}
		}
	}
}
