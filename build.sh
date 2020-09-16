go-bindata -o bindata.go js/chart.js js/utils.js index.html appinfo.html getinfo 
go build -o sshtool *.go
