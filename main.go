package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/miekg/dns"
)

func main() {

	target := os.Args[1]
	targetslices := strings.Split(target, ".")
	port := strings.Split(targetslices[0], "_")[1]
	proto := strings.Split(targetslices[1], "_")[1]
	fqdn := strings.Join(targetslices[2:], ".")
	server := "8.8.8.8"

	log.Printf("lookup: %s", target)
	log.Printf(" dnssrv: %s", server)
	log.Printf(" fqdn  : %s", fqdn)
	log.Printf(" proto : %s", proto)
	log.Printf(" port  : %s", port)

	c := dns.Client{}
	m := dns.Msg{}
	m.SetQuestion(target+".", dns.TypeTLSA)
	r, t, err := c.Exchange(&m, server+":53")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("DNS lookup took %v", t)
	if len(r.Answer) == 0 {
		log.Fatal("No results")
	}
	for _, ans := range r.Answer {
		log.Println(ans)
		TLSArecord := ans.(*dns.TLSA)
		tlsconfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		target = fmt.Sprintf("%s:%s", fqdn, port)
		log.Printf("Loading certificate from %s", target)
		conn, err := tls.Dial(proto, target, tlsconfig)
		if err != nil {
			log.Println(err)
		}
		state := conn.ConnectionState()
		cert := state.PeerCertificates[0]
		log.Printf(" certificate: O=%s, CN=%s", strings.Join(cert.Subject.Organization, " O="), cert.Subject.CommonName)
		conn.Close()
		h := sha256.New()
		h.Write(cert.Raw)
		certSHA256 := hex.EncodeToString(h.Sum(nil))
		log.Printf("TLSA record: %s", TLSArecord.Certificate)
		log.Printf("Cert sha256: %s", certSHA256)

		err = TLSArecord.Verify(cert)
		if err != nil {
			log.Println("ERROR      : Cert does not matches TLSA record.")
		} else {
			log.Println("OK         : Cert matches TLSA record.")
		}

	}
}
