package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/yl2chen/cidranger"
)

var cidrCache = make(map[string]cidranger.Ranger)
var torExitNodeCache []string
var log = logrus.New()

type Route struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
}
type Routes []Route

var routes = Routes{
	Route{
		"Index",
		"GET",
		"/",
		Index,
	},
	Route{
		"allowbycountry",
		"GET",
		"/allowbycountry/{country}/{ip}",
		allowbycountry,
	},
}

type jsonErr struct {
	Code int    `json:"code"`
	Text string `json:"text"`
}

type ConfigOptions struct {
	listenAddress    string
	port             string
	allowedCountries []string
	blockTor         bool
	cacheDirectory   string
}

var Config = ConfigOptions{
	"127.0.0.1",
	"9999",
	[]string{"us", "ca"},
	true,
	"./cache",
}

func main() {
	initLog()
	parseConfig()

	cacheCIDR(Config.allowedCountries)
	if Config.blockTor {
		cacheTORExitNodes()
	}
	var serverListenOn = Config.listenAddress + ":" + Config.port
	log.Info("Listening on " + serverListenOn)
	log.Fatal(http.ListenAndServe(serverListenOn, NewRouter()))

}

func initLog() {
	mkdirIFNotExists("./logs")

	logrus.SetFormatter(&logrus.TextFormatter{})

	file, err := os.OpenFile("./logs/nginxauth.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.Out = file
	} else {
		log.Info("Failed to log to file, using default stderr")
	}

}

func parseConfig() {
	viper.SetConfigName("nginxzoneauth")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc")
	viper.SetConfigType("json")
	if err := viper.ReadInConfig(); err != nil {
		log.Error("Error reading config file, %s", err)
	}
	Config.allowedCountries = viper.GetStringSlice("allowedCountries")
	Config.listenAddress = viper.GetString("listenAddress")
	Config.port = viper.GetString("port")
	Config.cacheDirectory = viper.GetString("cacheDirectory")
	Config.blockTor = viper.GetBool("blockTor")

}

func NewRouter() *mux.Router {

	router := mux.NewRouter().StrictSlash(true)
	for _, route := range routes {
		var handler http.Handler

		handler = route.HandlerFunc
		handler = httpLog(handler)

		router.
			Methods(route.Method).
			Path(route.Pattern).
			Name(route.Name).
			Handler(handler)
	}
	return router
}

func Index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Welcome!\n")
}

func allowbycountry(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var ip = vars["ip"]
	var country = vars["country"]

	//	log.Info("country requested=" + country + " ip=" + ip)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	if checkIPinRange(country, ip) {

		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(jsonErr{Code: http.StatusOK, Text: "Authorized"}); err != nil {
			log.Error(err)
		}

	} else {
		w.WriteHeader(http.StatusForbidden)
		if err := json.NewEncoder(w).Encode(jsonErr{Code: http.StatusForbidden, Text: "UnAuthorized"}); err != nil {
			log.Error(err)
		}
	}
	return
}
func httpLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Do stuff here
		log.WithFields(logrus.Fields{
			"RequestURI": r.RequestURI,
			"X-Real-IP":  r.Header.Get("X-Real-IP"),
		}).Info("")
		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(w, r)
	})
}

func cacheCIDR(countries []string) {
	cidrCache = make(map[string]cidranger.Ranger)
	for i := 0; i < len(countries); i++ {

		log.Info("looking for country " + countries[i])
		info, err := os.Stat(filepath.Join(Config.cacheDirectory, countries[i]+"-aggregated.zone"))
		if err == nil {
			delta := time.Now().Sub(info.ModTime())

			if delta.Hours() > 160 {
				url := "http://www.ipdeny.com/ipblocks/data/aggregated/" + countries[i] + "-aggregated.zone"
				downloadFromUrl(url, countries[i]+"-aggregated.zone")
			} else {
				log.Info(countries[i] + "-aggregated.zone is to new not downloading")
			}
		} else {
			url := "http://www.ipdeny.com/ipblocks/data/aggregated/" + countries[i] + "-aggregated.zone"
			downloadFromUrl(url, countries[i]+"-aggregated.zone")
		}
		readzonefile(countries[i])
	}
}

func cacheTORExitNodes() {
	log.Info("Inspecting tor exit node list")
	info, err := os.Stat(filepath.Join(Config.cacheDirectory, "tor-exit-nodes.txt"))
	if err == nil {
		delta := time.Now().Sub(info.ModTime())

		if delta.Hours() > 160 {
			url := "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=8.8.8.8"
			downloadFromUrl(url, "tor-exit-nodes.txt")
		} else {
			log.Info("tor exit node list is to new not downloading")
		}
	} else {
		url := "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=8.8.8.8"
		downloadFromUrl(url, "tor-exit-nodes.txt")
	}
	readTorExitNodes()
}

func checkIPinRange(country string, ip string) bool {

	if rangerCountry, ok := cidrCache[country]; ok {
		//do something here
		inCountry, err := rangerCountry.Contains(net.ParseIP(ip)) // returns true, nil
		if Config.blockTor {
			isNotTorExitNode := stringInSlice(ip, torExitNodeCache) // returns true, nil
			//flip the value since we want to know if they are NOT in the tor list
			if err != nil {
				log.Error(err)
			}
			isNotTorExitNode = !isNotTorExitNode
			return inCountry && isNotTorExitNode
		}
		log.WithFields(logrus.Fields{
			"ip":      ip,
			"country": country,
			"value":   strconv.FormatBool(inCountry),
		}).Info("")

		if err != nil {
			log.Error(err)
		}
		return inCountry
	} else {
		log.WithFields(logrus.Fields{
			"country": country,
		})
		log.Error("the country requested  is not in local zone cache, returning false")
		return false
	}
	return false
}

func readTorExitNodes() {
	var ipList []string
	file, err := os.Open(filepath.Join(Config.cacheDirectory, "tor-exit-nodes.txt"))
	if err != nil {
		log.Error(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		newIP := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(newIP, "#") {
			continue
		}

		if len("newIP") < 2 {
			continue
		}
		log.Info("adding " + scanner.Text())

		if net.ParseIP(newIP) != nil {
			ipList = append(ipList, newIP)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Error(err)
	}

	torExitNodeCache = ipList
}

func stringInSlice(str string, list []string) bool {
	for _, v := range list {
		if v == str {
			return true
		}
	}
	return false
}

func readzonefile(country string) {
	var ranger = cidranger.NewPCTrieRanger()
	file, err := os.Open(filepath.Join(Config.cacheDirectory, country+"-aggregated.zone"))
	if err != nil {
		log.Error(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		_, network, _ := net.ParseCIDR(scanner.Text())
		ranger.Insert(cidranger.NewBasicRangerEntry(*network))
		/* 	log.Info("adding " + scanner.Text()) */
	}

	if err := scanner.Err(); err != nil {
		log.Error(err)
	}

	cidrCache[country] = ranger
}

func downloadFromUrl(url string, fileName string) {
	//	tokens := strings.Split(url, "/")
	//	fileName := tokens[len(tokens)-1]

	log.Info("Downloading", url, "to", fileName)

	// TODO: check file existence first with io.IsExist
	mkdirIFNotExists(Config.cacheDirectory)
	output, err := os.Create(filepath.Join(Config.cacheDirectory, fileName))
	if err != nil {
		log.Info("Error while creating", fileName, "-", err)
		return
	}
	defer output.Close()

	response, err := http.Get(url)
	if err != nil {
		log.Info("Error while downloading", url, "-", err)
		return
	}
	defer response.Body.Close()

	n, err := io.Copy(output, response.Body)
	if err != nil {
		log.Info("Error while downloading", url, "-", err)
		return
	}

	log.Info(n, "bytes downloaded.")
}

func mkdirIFNotExists(path string) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		os.Mkdir(path, os.ModePerm)
	}
}
