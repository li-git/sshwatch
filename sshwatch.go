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
	"regexp"
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

type processSlice struct {
	Stamps  int64
	Time    string
	CpuInfo []int //  cpu
	MemInfo []int //  mem
}
type processpid struct {
	Name string
	Pid  string
}

var (
	httpserver     *string
	sshServer      *string
	sshPort        *int64
	sshUsername    *string
	sshPassword    *string
	cpuCores       int
	infoContain    []sliceData //for mpstate info
	processContain []processSlice
	processPid     []processpid //map processName,pid
)

func init() {
	httpserver = flag.String("httpserver", "0.0.0.0:888", "httpserver addr")
	sshServer = flag.String("sshServer", "10.100.123.246", "sshServer")
	sshPort = flag.Int64("sshPort", 2024, "ssh port")
	sshUsername = flag.String("sshUsername", "linuxadmin", "ssh username")
	sshPassword = flag.String("sshPassword", "sonus", "ssh password")
}

func main() {
	flag.Parse()
	cliConf := new(ClientConfig)
	cliConf.createClient(*sshServer, *sshPort, *sshUsername, *sshPassword)
	appInfo := RunShell(cliConf.Client, "sudo /etc/init.d/sbx status")
	scanner := bufio.NewScanner(strings.NewReader(appInfo))
	for scanner.Scan() {
		msg := scanner.Text()
		if strings.Contains(msg, "CE_2N_Comp_") {
			reg := regexp.MustCompile(`pid (\d+)`)
			pid := reg.FindStringSubmatch(msg)[1]
			reg = regexp.MustCompile(`(CE_2N_Comp_.*)\(`)
			processName := reg.FindStringSubmatch(msg)[1]
			log.Println("===> process ", processName, "  PID ", pid)
			//processPid[processName] = pid
			processPid = append(processPid, processpid{Name: processName, Pid: pid})
		}
	}
	{
		cpuinfo := RunShell(cliConf.Client, "grep -c processor /proc/cpuinfo")
		reg := regexp.MustCompile(`(\d+)`)
		cpuCores, _ = strconv.Atoi(reg.FindStringSubmatch(cpuinfo)[1])
		log.Println("cpucores ", cpuCores)
	}
	go cpuProcess(cliConf.Client)
	go sshSession(cliConf.Client)
	http_server_run(*httpserver)
}
func cpuProcess(client *ssh.Client) {
	totalCmd := `awk '{if ($1 == "cpu") {sum = $2 + $3 + $4 + $5 + $6 + $7 + $8 + $9 + $10 + $11;print sum}}' /proc/stat`
	type pidStruct struct {
		sample1 int
		total1  int
		sample2 int
		total2  int
		mem     int
		used    int
	}
	var pidSlice = make(map[string]pidStruct)
	for {
		for _, pinfo := range processPid {
			processCmd := `awk '{sum=$14 + $15;print sum}' /proc/` + pinfo.Pid + `/stat`
			processTime := getshellNumber(client, processCmd)
			totalTime := getshellNumber(client, totalCmd)
			pidStruct_ := pidStruct{sample1: processTime, total1: totalTime}
			pidSlice[pinfo.Name] = pidStruct_
		}

		time.Sleep(time.Second * 3)

		pSlice := processSlice{}
		pSlice.Stamps = time.Now().Unix()
		pSlice.Time = time.Now().Format("2006-01-02 15:04:05")

		for _, pinfo := range processPid {
			memCmd := `cat /proc/` + pinfo.Pid + `/status|grep -e VmRSS|awk '{print $2}'`
			processCmd := `awk '{sum=$14 + $15;print sum}' /proc/` + pinfo.Pid + `/stat`
			processTime := getshellNumber(client, processCmd)
			totalTime := getshellNumber(client, totalCmd)
			memUsed := getshellNumber(client, memCmd) / 1024

			pidStruct_ := pidSlice[pinfo.Name]
			pidStruct_.sample2 = processTime
			pidStruct_.total2 = totalTime
			pidStruct_.mem = memUsed
			pidStruct_.used = ((pidStruct_.sample2 - pidStruct_.sample1) * cpuCores * 100) / (pidStruct_.total2 - pidStruct_.total1)
			pidSlice[pinfo.Name] = pidStruct_

			pSlice.CpuInfo = append(pSlice.CpuInfo, pidStruct_.used)
			pSlice.MemInfo = append(pSlice.MemInfo, pidStruct_.mem)
		}
		processContain = append(processContain, pSlice)
		for index, tmpSlice := range processContain {
			if tmpSlice.Stamps < (time.Now().Unix() - 3600*12) {
				processContain = processContain[index:]
			} else {
				break
			}
		}
	}

}
func getNumber(str string) int {
	reg := regexp.MustCompile(`(\d+)`)
	ret, _ := strconv.Atoi(reg.FindStringSubmatch(str)[1])
	return ret
}
func getshellNumber(client *ssh.Client, shell string) int {
	session, err := client.NewSession()
	if err != nil {
		log.Fatalln(err)
	}
	output, err := session.CombinedOutput(shell)
	if err != nil {
		log.Fatalln(err)
	}
	session.Close()
	return getNumber(string(output))
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
	http.HandleFunc("/getprocessinfo", func(w http.ResponseWriter, r *http.Request) {
		var responseInfo map[string]interface{}
		responseInfo = make(map[string]interface{})
		var datas []processSlice

		s, _ := ioutil.ReadAll(r.Body)
		var req map[string]interface{}
		err := json.Unmarshal(s, &req)
		if err == nil && req["startTime"] != nil && req["endTime"] != nil && len(req["startTime"].(string)) > 0 && len(req["endTime"].(string)) > 0 {
			startStamp := transTime(req["startTime"].(string))
			endStamp := transTime(req["endTime"].(string))

			interval := processContain[1].Stamps - processContain[0].Stamps
			startPos := (startStamp - processContain[0].Stamps) / interval
			endPos := (endStamp - processContain[0].Stamps) / interval
			if startPos < 0 {
				startPos = 0
			}
			if endPos > int64(len(processContain)) {
				endPos = int64(len(processContain))
			}
			if int(startPos) > len(processContain)-1 {
				startPos = int64(len(processContain)) - 1
			}

			if int(endPos) > len(processContain)-1 {
				endPos = int64(len(processContain)) - 1
			}

			for index := startPos; index > 0; index-- {
				startPos = index
				if processContain[index].Stamps < startStamp {
					startStamp = index
					break
				}
			}
			for index := endPos; index < int64(len(processContain)); index++ {
				endPos = index
				if processContain[index].Stamps > endStamp {
					endPos = index
					break
				}
			}
			log.Println("start end time ", req["startTime"].(string), startStamp, req["endTime"].(string), endStamp)
			datas = processContain[startPos:endPos]
		} else {
			var start_pos int
			lens := len(processContain)
			if lens > 100 {
				start_pos = lens - 100
			} else {
				start_pos = 0
			}
			datas = processContain[start_pos : lens-1]
		}
		var labels []string
		for _, pinfo := range processPid {
			labels = append(labels, pinfo.Name)
		}
		responseInfo["data"] = datas
		responseInfo["labels"] = labels
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

	session.Run("mpstat -P ALL 5")
	//session.Run("tail -f /var/log/sonus/sbxPerf/mpstat.log")
}
func RunShell(client *ssh.Client, shell string) string {
	var (
		session *ssh.Session
		err     error
		output  []byte
	)
	if session, err = client.NewSession(); err != nil {
		log.Fatalln(err)
	}

	if output, err = session.CombinedOutput(shell); err != nil {
		log.Fatalln(err)
	}
	session.Close()
	return string(output)
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
				for index, tmpSlice := range infoContain {
					if tmpSlice.Stamps < (time.Now().Unix() - 3600*12) {
						infoContain = infoContain[index:]
					} else {
						break
					}
				}
			}
			cpuCore = 0
			cpuinfo = make(map[string]string)
		} else {
			if !strings.Contains(msg, "Linux") && !strings.Contains(msg, "usr") {
				splitStr := strings.Split(msg, " ")
				if len(splitStr) > 1 {
					cpuinfo["cpu"+strconv.Itoa(cpuCore)] = splitStr[len(splitStr)-1]
					cpuCore = cpuCore + 1
				}
			}
		}
	}
}
