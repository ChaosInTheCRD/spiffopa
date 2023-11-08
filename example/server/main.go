package main

import (
	"fmt"
	"github.com/chaosinthecrd/spiffopa/pkg/tls/tlsconfig"
	"github.com/gorilla/mux"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	stlsconfig "github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"net/http"
	"time"
)

type SPIFFESource struct {
}

func (s *SPIFFESource) GetX509SVID() (*x509svid.SVID, error) {
	return &x509svid.SVID{}, nil
}

func (s *SPIFFESource) GetX509BundleForTrustDomain(spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return &x509bundle.Bundle{}, nil
}

func main() {
	r := mux.NewRouter()

	s := &SPIFFESource{}
	tlsConfig := stlsconfig.MTLSServerConfig(s, s, tlsconfig.OPAAuthorize(fetchConfig("localhost:8080")))
	th := testHandler(time.RFC3339)
	r.Handle("/", th)
	server := &http.Server{
		Addr:              ":8443",
		Handler:           r,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: time.Second * 10,
	}

	if err := server.ListenAndServeTLS("", ""); err != nil {
		panic(fmt.Errorf("failed to serve: %w", err))
	}
	err := http.ListenAndServe(":8080", r)
	if err != nil {
		panic(err)
	}
}

func testHandler(format string) http.Handler {
	// vars := mux.Vars(r)
	fn := func(w http.ResponseWriter, r *http.Request) {
		tm := time.Now().Format(format)
		_, err := w.Write([]byte("The time is: " + tm))
		if err != nil {
			panic(err)
		}
	}
	return http.HandlerFunc(fn)
}

func fetchConfig(url string) []byte {
	// provide the OPA configuration which specifies
	// fetching policy bundles from the mock server
	// and logging decisions locally to the console
	config := []byte(fmt.Sprintf(`{
		"services": {
			"test": {
				"url": %q
			}
		},
		"bundles": {
			"test": {
				"resource": "/bundles/bundle.tar.gz"
			}
		},
		"decision_logs": {
			"console": true
		}
	}`, url))

	return config
}
