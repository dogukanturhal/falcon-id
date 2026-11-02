// SPDX-License-Identifier: AGPL-3.0-or-later

// Command saml-cert-audit is a READ-ONLY report of the IdP certificate on
// every SAML SP identity provider row: whether one is present, whether it
// parses as an X.509 certificate, its expiry, and its declared signature
// algorithm. It issues a single SELECT and never writes to the database.
//
// It exists to size the blast radius before SAML signature verification
// enforcement is turned on: a tenant whose idp_certificate is missing, does
// not parse, or has already expired will fail authentication the moment
// verification is enforced, so this report is how that population gets
// found ahead of time instead of during an incident.
//
// Usage:
//
//	DATABASE_URL=postgres://... go run ./cmd/saml-cert-audit
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// samlCertAuditQuery selects every SAML SP identity provider row along with
// its tenant and the raw saml_sp_config JSON blob. Certificate parsing
// happens in Go below, not in SQL, since idp_certificate is nested inside
// the saml_sp_config jsonb column rather than being its own column.
const samlCertAuditQuery = `
SELECT ip.id, ip.tenant_id, t.name, ip.saml_sp_config
FROM iam_identity_providers ip
JOIN iam_tenants t ON t.id = ip.tenant_id
WHERE ip.provider_type = 'saml'
ORDER BY t.name, ip.id
`

type row struct {
	id         string
	tenantID   string
	tenantName string
}

type report struct {
	id           string
	tenant       string
	certPresent  bool
	certParses   bool
	expiry       string
	sigAlgorithm string
	parseError   string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "saml-cert-audit:", err)
		os.Exit(1)
	}
}

func run() error {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return fmt.Errorf("DATABASE_URL is required (read-only query, no credentials embedded in this tool)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer pool.Close()

	rows, err := pool.Query(ctx, samlCertAuditQuery)
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	var results []report
	for rows.Next() {
		var r row
		var configJSON []byte
		if err := rows.Scan(&r.id, &r.tenantID, &r.tenantName, &configJSON); err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		results = append(results, auditRow(r, configJSON))
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("row iteration: %w", err)
	}

	printReport(results)
	return nil
}

func auditRow(r row, configJSON []byte) report {
	out := report{id: r.id, tenant: r.tenantName}

	var cfg struct {
		IDPCertificate string `json:"idp_certificate"`
	}
	if len(configJSON) > 0 {
		if err := json.Unmarshal(configJSON, &cfg); err != nil {
			out.parseError = fmt.Sprintf("saml_sp_config JSON: %v", err)
			return out
		}
	}

	if cfg.IDPCertificate == "" {
		return out
	}
	out.certPresent = true

	cert, err := parseCertificate(cfg.IDPCertificate)
	if err != nil {
		out.parseError = err.Error()
		return out
	}

	out.certParses = true
	out.expiry = cert.NotAfter.Format(time.RFC3339)
	out.sigAlgorithm = cert.SignatureAlgorithm.String()
	return out
}

// parseCertificate accepts either PEM-wrapped or raw base64/DER certificate
// bytes, since idp_certificate is stored inconsistently across the fleet.
func parseCertificate(raw string) (*x509.Certificate, error) {
	der := []byte(raw)
	if block, _ := pem.Decode([]byte(raw)); block != nil {
		der = block.Bytes
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("does not parse as X.509: %w", err)
	}
	return cert, nil
}

func printReport(results []report) {
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "TENANT\tPROVIDER_ID\tCERT_PRESENT\tPARSES\tEXPIRY\tSIG_ALGORITHM\tNOTE")

	var missing, unparseable, expired int
	now := time.Now()
	for _, r := range results {
		note := r.parseError
		if r.certParses {
			if expiry, err := time.Parse(time.RFC3339, r.expiry); err == nil && expiry.Before(now) {
				note = "EXPIRED"
				expired++
			}
		}
		if !r.certPresent {
			missing++
		} else if !r.certParses {
			unparseable++
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%v\t%v\t%s\t%s\t%s\n",
			r.tenant, r.id, r.certPresent, r.certParses, r.expiry, r.sigAlgorithm, note)
	}
	_ = w.Flush()

	fmt.Printf("\n%d SAML SP providers audited: %d missing certificate, %d unparseable, %d expired\n",
		len(results), missing, unparseable, expired)
}
