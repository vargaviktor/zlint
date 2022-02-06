/*
 * ZLint Copyright 2021 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package cabf_br

import (
	"fmt"
	"strings"
	"time"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:            "e_underscore_permissible_in_dnsname_if_valid_when_replaced",
		Description:     "From December 10th 2018 to April 1st 2019 DNSNames may contain underscores if-and-only-if every label withing each DNS name is a valid LDH label after replacing all underscores with hyphens",
		Citation:        "Prior to April 1 2019, certificates containing underscore characters (“_”) in domain labels in dNSName entries MAY be issued as follows...dNSName entries MAY include underscore characters such that replacing all underscore characters with hyphen characters (“-“) would result in a valid domain label.",
		Source:          lint.CABFBaselineRequirements,
		EffectiveDate:   util.CABFBRs_1_6_2_Date,
		IneffectiveDate: time.Date(2019, time.April, 1, 0, 0, 0, 0, time.UTC),
		Lint:            func() lint.LintInterface { return &UnderscorePermissibleInDNSNameIfValidWhenReplaced{} },
	})
}

type UnderscorePermissibleInDNSNameIfValidWhenReplaced struct{}

func (l *UnderscorePermissibleInDNSNameIfValidWhenReplaced) CheckApplies(c *x509.Certificate) bool {
	return util.IsSubscriberCert(c) && util.DNSNamesExist(c)
}

func (l *UnderscorePermissibleInDNSNameIfValidWhenReplaced) Execute(c *x509.Certificate) *lint.LintResult {
	for _, dns := range c.DNSNames {
		for _, label := range strings.Split(dns, ".") {
			replaced := strings.ReplaceAll(label, "_", "-")
			if !util.IsLDHLabel(replaced) {
				return &lint.LintResult{Status: lint.Error, Details: fmt.Sprintf("When all underscores (_) in '%s' are replaced with hypens (-) the result is '%s' which not a valid LDH label", label, replaced)}
			}
		}
	}
	return &lint.LintResult{Status: lint.Pass}
}
