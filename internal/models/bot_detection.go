// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"regexp"
	"time"

	"github.com/google/uuid"
)

// BotDetectionAction is the recommended enforcement action for a request.
type BotDetectionAction string

const (
	// BotActionAllow passes the request through with a recorded bot score.
	BotActionAllow BotDetectionAction = "allow"
	// BotActionChallenge requires the caller to solve an additional challenge
	// (CAPTCHA or proof-of-work) before the request is accepted.
	BotActionChallenge BotDetectionAction = "challenge"
	// BotActionBlock rejects the request outright.
	BotActionBlock BotDetectionAction = "block"
)

// BotChallengeType describes which challenge the client must solve.
type BotChallengeType string

const (
	// BotChallengeNone is an exported identifier.
	BotChallengeNone BotChallengeType = "none"
	// BotChallengeCAPTCHA is an exported identifier.
	BotChallengeCAPTCHA BotChallengeType = "captcha"
	// BotChallengeProofOfWork is an exported identifier.
	BotChallengeProofOfWork BotChallengeType = "proof_of_work"
)

// BotSignalType classifies the evidence that contributed to the bot score.
type BotSignalType string

const (
	// BotSignalRate is an exported identifier.
	BotSignalRate BotSignalType = "rate"
	// BotSignalUserAgent is an exported identifier.
	BotSignalUserAgent BotSignalType = "user_agent"
	// BotSignalIPReputation is an exported identifier.
	BotSignalIPReputation BotSignalType = "reputation"
	// BotSignalFingerprint is an exported identifier.
	BotSignalFingerprint BotSignalType = "fingerprint"
	// BotSignalCredVelocity is an exported identifier.
	BotSignalCredVelocity BotSignalType = "credential_velocity" //nolint:gosec // not a credential, this is a bot detection indicator name constant
	// BotSignalGeoImpossible is an exported identifier.
	BotSignalGeoImpossible BotSignalType = "geo_impossible"
)

// BotSignal is a single piece of evidence that influenced the bot score.
type BotSignal struct {
	// Type classifies the source of evidence.
	Type BotSignalType `json:"type"`
	// Score is the contribution of this signal to the overall bot score (0.0–1.0).
	Score float64 `json:"score"`
	// Detail is a human-readable description of why this signal fired.
	Detail string `json:"detail"`
}

// BotDetectionResult is the output of a full bot-detection evaluation pass.
type BotDetectionResult struct {
	// IsBot is true when the composite score exceeds the block threshold.
	IsBot bool `json:"is_bot"`
	// Score is the composite bot-likelihood score in [0.0, 1.0].
	// 0.0 = definitely human; 1.0 = definitely a bot.
	Score float64 `json:"score"`
	// Signals is the ordered list of evidence that contributed to Score.
	Signals []BotSignal `json:"signals"`
	// Action is the recommended enforcement decision.
	Action BotDetectionAction `json:"action"`
	// ChallengeType is only meaningful when Action == BotActionChallenge.
	ChallengeType BotChallengeType `json:"challenge_type"`
}

// BotDetectionEvent is written to the audit store whenever a request is
// evaluated by the bot-detection engine. It provides an immutable record for
// security analysis and tuning.
type BotDetectionEvent struct {
	ID        uuid.UUID          `json:"id" db:"id"`
	IP        string             `json:"ip" db:"ip"`
	UserAgent string             `json:"user_agent" db:"user_agent"`
	Path      string             `json:"path" db:"path"`
	Score     float64            `json:"score" db:"score"`
	Action    BotDetectionAction `json:"action" db:"action"`
	Signals   []BotSignal        `json:"signals" db:"signals"`
	TenantID  *uuid.UUID         `json:"tenant_id,omitempty" db:"tenant_id"`
	CreatedAt time.Time          `json:"created_at" db:"created_at"`
}

// IPReputation maps an IP address to a pre-computed reputation score.
// Scores are maintained in Redis sets; this struct is used for in-process
// representations when multiple score sources are combined.
type IPReputation struct {
	IP         string    `json:"ip"`
	Score      float64   `json:"score"`      // 0.0 (clean) – 1.0 (known malicious)
	Categories []string  `json:"categories"` // e.g. ["tor", "datacenter", "proxy"]
	LastSeenAt time.Time `json:"last_seen_at"`
	Source     string    `json:"source"` // "static", "dynamic", "external"
}

// knownBotUAPatterns is the list of compiled regular expressions matched against
// the User-Agent header. Any match contributes a high signal score.
//
// The patterns are intentionally conservative: they target unambiguous bot
// indicators (headless browsers, scraper libraries, empty UAs) rather than
// legitimate automation clients such as monitoring agents.
var knownBotUAPatterns = []*regexp.Regexp{
	// Headless / automated browsers
	regexp.MustCompile(`(?i)HeadlessChrome`),
	regexp.MustCompile(`(?i)PhantomJS`),
	regexp.MustCompile(`(?i)Puppeteer`),
	regexp.MustCompile(`(?i)Playwright`),
	regexp.MustCompile(`(?i)Selenium`),
	regexp.MustCompile(`(?i)WebDriver`),
	regexp.MustCompile(`(?i)htmlunit`),
	regexp.MustCompile(`(?i)slimerjs`),

	// Common scripting / HTTP client libraries
	regexp.MustCompile(`(?i)python-requests`),
	regexp.MustCompile(`(?i)python-urllib`),
	regexp.MustCompile(`(?i)aiohttp`),
	regexp.MustCompile(`(?i)httpx`),
	regexp.MustCompile(`(?i)^curl/`),
	regexp.MustCompile(`(?i)^Go-http-client/`),
	regexp.MustCompile(`(?i)^Java/`),
	regexp.MustCompile(`(?i)^okhttp/`),
	regexp.MustCompile(`(?i)^axios/`),
	regexp.MustCompile(`(?i)node-fetch`),
	regexp.MustCompile(`(?i)^Wget/`),
	regexp.MustCompile(`(?i)libwww-perl`),
	regexp.MustCompile(`(?i)Ruby`),

	// Known scanning / credential-stuffing tools
	regexp.MustCompile(`(?i)masscan`),
	regexp.MustCompile(`(?i)nikto`),
	regexp.MustCompile(`(?i)sqlmap`),
	regexp.MustCompile(`(?i)dirbuster`),
	regexp.MustCompile(`(?i)hydra`),
	regexp.MustCompile(`(?i)medusa`),
	regexp.MustCompile(`(?i)nmap`),
	regexp.MustCompile(`(?i)zgrab`),
}

// KnownBotUAPatterns returns the compiled UA pattern list so that callers in
// the services package can reference the singleton without re-compiling.
func KnownBotUAPatterns() []*regexp.Regexp {
	return knownBotUAPatterns
}
