package findings

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/tobiasGuta/Reconductor/internal/domain"
)

type CandidateStatus string

const (
	New           CandidateStatus = "new"
	Queued        CandidateStatus = "queued_for_verification"
	Verifying     CandidateStatus = "verifying"
	Confirmed     CandidateStatus = "confirmed"
	Rejected      CandidateStatus = "rejected"
	Informational CandidateStatus = "informational"
	ManualReview  CandidateStatus = "needs_manual_review"
)

type Candidate struct {
	ID                   domain.ID       `json:"id"`
	TaskID               domain.ID       `json:"task_id"`
	WorkflowRunID        domain.ID       `json:"workflow_run_id"`
	TargetAssetID        domain.ID       `json:"target_asset_id"`
	SourceCapability     string          `json:"source_capability"`
	TemplateID           string          `json:"template_id"`
	ClaimedVulnerability string          `json:"claimed_vulnerability"`
	Severity             string          `json:"severity"`
	EvidenceArtifactIDs  []domain.ID     `json:"evidence_artifact_ids"`
	DetectionConfidence  float64         `json:"detection_confidence"`
	Status               CandidateStatus `json:"status"`
	CreatedAt            time.Time       `json:"created_at"`
	UpdatedAt            time.Time       `json:"updated_at"`
}
type Verdict string

const (
	VerdictConfirmed    Verdict = "confirmed"
	VerdictRejected     Verdict = "rejected"
	VerdictInconclusive Verdict = "inconclusive"
	VerdictManual       Verdict = "manual_review"
)

type VerificationInput struct {
	URL                       string              `json:"url"`
	StatusCode                int                 `json:"status_code"`
	Headers                   map[string][]string `json:"headers"`
	Body                      json.RawMessage     `json:"body"`
	UnauthenticatedStatusCode int                 `json:"unauthenticated_status_code"`
}
type Verification struct {
	Playbook string  `json:"playbook"`
	Verdict  Verdict `json:"verdict"`
	Summary  string  `json:"summary"`
}

func Transition(from, to CandidateStatus) error {
	allowed := map[CandidateStatus]map[CandidateStatus]bool{New: {Queued: true, Informational: true, ManualReview: true}, Queued: {Verifying: true}, Verifying: {Confirmed: true, Rejected: true, ManualReview: true}}
	if !allowed[from][to] {
		return fmt.Errorf("invalid candidate transition %s -> %s", from, to)
	}
	return nil
}
func Verify(playbook string, in VerificationInput) Verification {
	body := strings.ToLower(string(in.Body))
	switch playbook {
	case "exposed-file":
		if in.StatusCode == 200 && (strings.Contains(body, "private key") || strings.Contains(body, "database_password") || strings.Contains(body, "aws_access_key_id")) {
			return Verification{playbook, VerdictConfirmed, "independent response evidence contains an exposed-file marker"}
		}
	case "openapi":
		if in.StatusCode == 200 && (strings.Contains(body, `"openapi"`) || strings.Contains(body, `"swagger"`)) && strings.Contains(body, `"paths"`) {
			return Verification{playbook, VerdictConfirmed, "response parses as a public API description candidate"}
		}
	case "graphql-introspection":
		if in.StatusCode == 200 && strings.Contains(body, `"__schema"`) {
			return Verification{playbook, VerdictConfirmed, "GraphQL schema evidence was returned"}
		}
	case "open-redirect":
		u, err := url.Parse(in.URL)
		if err == nil {
			for _, v := range in.Headers["Location"] {
				loc, e := url.Parse(v)
				if e == nil && loc.IsAbs() && !strings.EqualFold(loc.Hostname(), u.Hostname()) {
					return Verification{playbook, VerdictConfirmed, "redirect location points to the configured external verification origin"}
				}
			}
		}
	case "cors-reflection":
		origin := first(in.Headers["X-Verification-Origin"])
		allow := first(in.Headers["Access-Control-Allow-Origin"])
		if origin != "" && origin == allow {
			return Verification{playbook, VerdictConfirmed, "arbitrary verification origin was reflected"}
		}
	case "missing-authentication":
		if in.UnauthenticatedStatusCode >= 200 && in.UnauthenticatedStatusCode < 300 {
			return Verification{playbook, VerdictManual, "endpoint responded without credentials; authorization and impact require human review"}
		}
	default:
		return Verification{playbook, VerdictInconclusive, "unknown verification playbook"}
	}
	return Verification{playbook, VerdictRejected, "independent confirmation criteria were not met"}
}
func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}
