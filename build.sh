go-bindata -o bindata.go js/chart.js js/utils.js index.html getinfo
go build -o sshtool *.go
