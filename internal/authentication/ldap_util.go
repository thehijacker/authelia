package authentication

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

func ldapEntriesContainsEntry(needle *ldap.Entry, haystack []*ldap.Entry) bool {
	if needle == nil || len(haystack) == 0 {
		return false
	}

	for i := 0; i < len(haystack); i++ {
		if haystack[i].DN == needle.DN {
			return true
		}
	}

	return false
}

func ldapGetFeatureSupportFromEntry(entry *ldap.Entry) (controlTypeOIDs, extensionOIDs []string, features LDAPSupportedFeatures) {
	if entry == nil {
		return controlTypeOIDs, extensionOIDs, features
	}

	for _, attr := range entry.Attributes {
		switch attr.Name {
		case ldapSupportedControlAttribute:
			controlTypeOIDs = attr.Values

			for _, oid := range attr.Values {
				switch oid {
				case ldapOIDControlMsftServerPolicyHints:
					features.ControlTypes.MsftPwdPolHints = true
				case ldapOIDControlMsftServerPolicyHintsDeprecated:
					features.ControlTypes.MsftPwdPolHintsDeprecated = true
				}
			}
		case ldapSupportedExtensionAttribute:
			extensionOIDs = attr.Values

			for _, oid := range attr.Values {
				switch oid {
				case ldapOIDExtensionPwdModifyExOp:
					features.Extensions.PwdModifyExOp = true
				case ldapOIDExtensionTLS:
					features.Extensions.TLS = true
				}
			}
		}
	}

	return controlTypeOIDs, extensionOIDs, features
}

func ldapEscape(inputUsername string) string {
	inputUsername = ldap.EscapeFilter(inputUsername)
	for _, c := range specialLDAPRunes {
		inputUsername = strings.ReplaceAll(inputUsername, string(c), fmt.Sprintf("\\%c", c))
	}

	return inputUsername
}

func (p *LDAPUserProvider) logLDAPError(err *ldap.Error) {
	p.log.WithField("code", err.ResultCode).WithField("matched_dn", err.MatchedDN).WithError(err.Err).Debug("Error Headers")

	if err.Packet == nil {
		return
	}

	packet, _ := json.Marshal(err.Packet)

	p.log.WithField("packetJSON", base64.StdEncoding.EncodeToString(packet)).WithField("packetBytes", base64.StdEncoding.EncodeToString(err.Packet.Bytes())).Debug("Packet Data Dump")
}

func (p *LDAPUserProvider) ldapGetReferral(err error) (referral string, ok bool) {
	switch e := err.(type) {
	case *ldap.Error:
		p.logLDAPError(e)

		if e.ResultCode != ldap.LDAPResultReferral {
			p.log.Debugf("Lookup of referral skipped for error %v: is not error with code", err)

			return "", false
		}

		if e.Packet == nil {
			p.log.Debugf("Lookup of referral skipped for error %v: packet is empty", err)

			return "", false
		}

		children := len(e.Packet.Children)

		if children < 2 {
			p.log.WithField("children", children).Debugf("Lookup of referral skipped for error %v: packet does not have enough children", err)

			return "", false
		}

		if e.Packet.Children[1].Tag != ber.TagObjectDescriptor {
			p.log.WithField("tag", e.Packet.Children[1].Tag).Debugf("Lookup of referral skipped for error %v: packet child 2 does not have a tag object descriptor", err)

			return "", false
		}

		for i := 0; i < len(e.Packet.Children[1].Children); i++ {
			if e.Packet.Children[1].Children[i].Tag != ber.TagBitString {
				p.log.WithField("subchild", i).WithField("tag", e.Packet.Children[1].Children[i].Tag).Debug("Sub-Child is being skipped as it's not tagged as a bit string")

				continue
			}

			if len(e.Packet.Children[1].Children[i].Children) < 1 {
				p.log.WithField("subchild", i).Debug("Sub-Child is being skipped as it has no children")

				continue
			}

			referral, ok = e.Packet.Children[1].Children[i].Children[0].Value.(string)

			if !ok {
				p.log.WithField("subchild", i).Debug("Sub-Child is being skipped as it didn't have a string value")

				continue
			}

			p.log.WithField("referral", referral).Debug("Referral found")

			return referral, true
		}

		p.log.WithField("children", children).Debugf("Lookup of referral skipped for error %v: packet does not have the expected attributes", err)

		return "", false
	default:
		p.log.WithError(err).Debugf("Received unknown type %T", e)

		return "", false
	}
}
