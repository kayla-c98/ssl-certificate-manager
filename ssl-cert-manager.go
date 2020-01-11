package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/go-acme/lego/certcrypto"
	"github.com/go-acme/lego/certificate"
	"github.com/go-acme/lego/registration"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/xenolf/lego/lego"
	"github.com/xenolf/lego/providers/dns/digitalocean"
)

type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

type Certificate struct {
	Certificate string `json:"Certificate"`
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func main() {
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/ssl-cert/{domain}", GetCert).Methods("GET")
	router.HandleFunc("/ssl-cert/{domain}", DeleteCert).Methods("DELETE")
	router.HandleFunc("/ssl-cert/{domain}", RequestCert)
	log.Fatal(http.ListenAndServe(":8080", router))
}

// GenerateFreeSSLCerts requests/generate Cert and uploads it to db
func GenerateFreeSSLCerts(domain string, email string) {
	// Create a user. New accounts need an email and private key to start.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	// TODO apply real user email information passed as CLI params
	myUser := MyUser{
		Email: email,
		key:   privateKey,
	}

	config := lego.NewConfig(&myUser)

	// This is the ACME URL for ACME v2 staging environment
	config.CADirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	//config.CADirURL = "https://acme-v02.api.letsencrypt.org/directory"
	config.Certificate.KeyType = certcrypto.RSA2048

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	providerConfig := digitalocean.NewDefaultConfig()
	// FIXME implement secure way to retrieve API access token (maybe as an environment variable)
	// Also, replace the DNS provider with DNS Made Easy
	providerConfig.AuthToken = ""
	provider, err := digitalocean.NewDNSProviderConfig(providerConfig)
	if err != nil {
		log.Fatal(err)
	}
	err = client.Challenge.SetDNS01Provider(provider)
	if err != nil {
		log.Fatal(err)
	}
	// New users will need to register
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		log.Fatal(err)
	}
	myUser.Registration = reg
	fmt.Printf("%+v\n", reg)

	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}
	/*
		err = StoreCertsLocally(certificates)
		if err != nil {
			log.Fatal(err)
		}*/

	err = AddCertsToDb(certificates, domain)
	if err != nil {
		log.Fatal(err)
	}
}

// StoreCertsLocally saves certs as local files
func StoreCertsLocally(certificates *certificate.Resource) error {
	/* write byte arrays in certificates to respective files stored in
	   the certificates directory */
	err := WriteBytesToFile("certificates/privatekey.key", certificates.PrivateKey)
	if err != nil {
		return err
	}

	err = WriteBytesToFile("certificates/issuercert.cert", certificates.IssuerCertificate)
	if err != nil {
		return err
	}

	err = WriteBytesToFile("certificates/certificate.cert", certificates.Certificate)
	if err != nil {
		return err
	}
	return nil
}

// AddCertsToDb uploads certs as strings to local MySql db
func AddCertsToDb(certificates *certificate.Resource, domain string) error {
	db, err := sql.Open("mysql", "root:password@tcp(127.0.0.1:3306)/domain_certs_db")
	if err != nil {
		return err
	}

	defer db.Close()

	insert, err := db.Query(fmt.Sprintf("INSERT INTO domain_certs_table(domain, private_key, issuer_cert, cert) VALUES ('%s','%s','%s','%s')",
		domain, string(certificates.PrivateKey[:]),
		string(certificates.IssuerCertificate[:]), string(certificates.Certificate[:])))
	if err != nil {
		return err
	}

	defer insert.Close()
	return nil
}

// RemoveCertFromDb deletes row from db table based of primary key domain
func RemoveCertFromDb(domain string) error {
	db, err := sql.Open("mysql", "root:password@tcp(127.0.0.1:3306)/domain_certs_db")
	if err != nil {
		return err
	}

	defer db.Close()

	insert, err := db.Query(fmt.Sprintf("DELETE FROM domain_certs_table WHERE domain = '%s'",
		domain))
	if err != nil {
		return err
	}

	defer insert.Close()
	return nil
}

// GetCertFromDb gets cert from db from domain primary key
func GetCertFromDb(domain string) Certificate {
	db, err := sql.Open("mysql", "root:password@tcp(127.0.0.1:3306)/domain_certs_db")
	if err != nil {
		log.Fatal(err)
	}

	defer db.Close()

	var cert Certificate
	err = db.QueryRow(`SELECT cert FROM domain_certs_table WHERE domain =?`, domain).Scan(&cert.Certificate)
	if err != nil {
		log.Fatal(err)
	}

	return cert
}

// GetCert is function called when /get-cert/{domain} is hit
func GetCert(w http.ResponseWriter, r *http.Request) {
	domain := mux.Vars(r)["domain"]

	var cert = GetCertFromDb(domain)

	json.NewEncoder(w).Encode(cert)
}

// RequestCert is function called when /get-cert/{domain} is hit
func RequestCert(w http.ResponseWriter, r *http.Request) {
	domain := mux.Vars(r)["domain"]
	email := mux.Vars(r)["email"]

	GenerateFreeSSLCerts(domain, email)

	fmt.Fprintf(w, "Certs for domain \""+domain+"\" successfully generated")
}

// DeleteCert is called when /delete-cert/{domain} is hit
func DeleteCert(w http.ResponseWriter, r *http.Request) {
	domain := mux.Vars(r)["domain"]

	// TODO not sure how to respond...
	RemoveCertFromDb(domain)
}

// WriteBytesToFile writes bytes to file
func WriteBytesToFile(pathName string, bytes []byte) error {
	f, err := os.Create(pathName)
	if err != nil {
		return err
	}

	n2, err := f.Write(bytes)
	if err != nil {
		f.Close()
		return err
	}

	err = f.Close()
	if err != nil {
		return err
	}

	fmt.Println(n2, "bytes written successfully")
	return nil
}
