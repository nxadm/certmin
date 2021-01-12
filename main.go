package main

const (
	version = "0.2.0"
	website = "https://github.com/nxadm/certmin"
)

func main() {
	action, _ := getAction()
	action()
}
