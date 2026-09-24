package mq

import (
	"context"
	"time"

	"github.com/BillShiyaoZhang/agent-comm/v2"
)

const v2PolicyPath = "/api/v2/policy"

// PolicyDiscovery contains only public facts from the currently pinned,
// root-signed policy. Its HTTP representation is a discovery hint, not a
// substitute for verifying the policy with an independently pinned root.
type PolicyDiscovery struct {
	PolicyURL       string `json:"policy_url"`
	PolicyHash      string `json:"policy_hash"`
	PolicyEpoch     uint64 `json:"policy_epoch"`
	PolicyMode      string `json:"policy_mode"`
	PlatformID      string `json:"platform_id"`
	UpgradeRequired bool   `json:"upgrade_required"`
	ConsentRequired bool   `json:"consent_required"`
}

// DescribeV2Policy withholds stale or expired policy hints, including when
// the mailbox remembers a later epoch than the loaded gateway configuration.
func DescribeV2Policy(ctx context.Context, store *Store, gateway *V2Gateway) *PolicyDiscovery {
	if store == nil || gateway == nil || gateway.CheckCurrent() != nil {
		return nil
	}
	hash := v2.PolicyHash(gateway.Policy)
	if hash == "" || v2.EnvelopeHash(gateway.RawPolicy) != hash {
		return nil
	}
	var pinnedEpoch uint64
	var pinnedHash string
	var pinnedExpiry int64
	err := store.db.QueryRowContext(ctx, "SELECT epoch,policy_hash,expires_at FROM v2_policy_state WHERE singleton=1").Scan(&pinnedEpoch, &pinnedHash, &pinnedExpiry)
	if err != nil || pinnedEpoch != gateway.Policy.Epoch || pinnedHash != hash || time.Now().Unix() >= pinnedExpiry {
		return nil
	}
	return &PolicyDiscovery{
		PolicyURL:       v2PolicyPath,
		PolicyHash:      hash,
		PolicyEpoch:     gateway.Policy.Epoch,
		PolicyMode:      gateway.Policy.Mode,
		PlatformID:      gateway.Policy.PlatformID,
		UpgradeRequired: !gateway.Policy.AllowV1,
		ConsentRequired: gateway.Policy.Mode == v2.ModeCompliance,
	}
}

// V1UpgradeNotice is returned only when the shared mailbox rejects a v1
// store under its pinned policy. A null consent_required means no current
// signed policy can be offered; it must not be interpreted as consent.
type V1UpgradeNotice struct {
	Error           string `json:"error"`
	Message         string `json:"message"`
	ConsentRequired *bool  `json:"consent_required"`
	PolicyURL       string `json:"policy_url,omitempty"`
	PolicyHash      string `json:"policy_hash,omitempty"`
	PolicyEpoch     uint64 `json:"policy_epoch,omitempty"`
	PolicyMode      string `json:"policy_mode,omitempty"`
	PlatformID      string `json:"platform_id,omitempty"`
}

func NewV1UpgradeNotice(policy *PolicyDiscovery) V1UpgradeNotice {
	notice := V1UpgradeNotice{
		Error:   "upgrade_required",
		Message: "v1 delivery is disabled; no current signed v2 policy is available from this server",
	}
	if policy != nil && policy.UpgradeRequired {
		notice.Message = "v1 delivery is disabled; verify the signed v2 policy and upgrade before retrying"
		consent := policy.ConsentRequired
		notice.ConsentRequired = &consent
		notice.PolicyURL = policy.PolicyURL
		notice.PolicyHash = policy.PolicyHash
		notice.PolicyEpoch = policy.PolicyEpoch
		notice.PolicyMode = policy.PolicyMode
		notice.PlatformID = policy.PlatformID
	}
	return notice
}
