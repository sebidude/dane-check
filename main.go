package main

import (
	"crypto/tls"
	"fmt"
	"github.com/alecthomas/kingpin"
	"os"

	"github.com/miekg/dns"
)

var (
	dnsserver string
	target    string
	port      string
)

func main() {

	app := kingpin.New(os.Args[0], "Check TLSA RR against the target using a specific nameserver.")
	app.UsageTemplate(kingpin.CompactUsageTemplate)
	app.Flag("dnsserver", "The dnsserver to use for the lookup.").Short('d').Default("8.8.8.8").StringVar(&dnsserver)
	app.Flag("target", "The domain name to be checked").Short('t').Default("localhost").StringVar(&target)
	app.Flag("port", "The port on which the target presents the cert.").Short('p').Default("443").StringVar(&port)
	kingpin.MustParse(app.Parse(os.Args[1:]))

	fmt.Printf("Dane check for: %s\n", target)
	fmt.Printf(" dnsserver: %s\n", dnsserver)
	fmt.Printf(" target   : %s\n", target)
	fmt.Printf(" port     : %s\n", port)

	c := dns.Client{}
	m := dns.Msg{}
	rrstring := "_" + port + "._tcp." + target
	m.SetQuestion(rrstring+".", dns.TypeTLSA)
	fmt.Printf("\nLooking up %s\n", rrstring)
	r, t, err := c.Exchange(&m, dnsserver+":53")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("DNS lookup took %v\n\n", t)
	if len(r.Answer) == 0 {
		fmt.Println("No results")
		os.Exit(1)
	}
	for _, ans := range r.Answer {
		TLSArecord := ans.(*dns.TLSA)
		fmt.Println("TLSA Record:")
		fmt.Printf(" Usage       : %d\n", TLSArecord.Usage)
		fmt.Printf(" Selector    : %d\n", TLSArecord.Selector)
		fmt.Printf(" MatchingType: %d\n", TLSArecord.MatchingType)
		fmt.Printf(" CertData    : %s\n", TLSArecord.Certificate)

		tlsconfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		target = fmt.Sprintf("%s:%s", target, port)
		fmt.Printf("\nLoading certificate from %s\n", target)
		conn, err := tls.Dial("tcp", target, tlsconfig)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		state := conn.ConnectionState()
		cert := state.PeerCertificates[0]
		fmt.Printf(" certificate: CN=%s\n", cert.Subject.CommonName)
		conn.Close()
		err = TLSArecord.Verify(cert)
		if err != nil {
			fmt.Println("ERROR      : Cert does not matches TLSA record.")
			os.Exit(1)
		} else {
			fmt.Println("OK         : Cert matches TLSA record.")
		}

	}
}
