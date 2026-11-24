// Command validate-specs checks the conventions that Spectral cannot express across documents:
// every x-permission appears in common/permissions.yaml, the catalogue flag rules hold, realms and
// paths agree, x-service-callers marks exactly the /internal/v1 operations, and x-vendor-audit: none
// is used on directory-class operations only. Usage: validate-specs <repo-root>.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type perm struct {
	Key     string   `yaml:"key"`
	Realm   string   `yaml:"realm"`
	Service string   `yaml:"service"`
	DescKey string   `yaml:"description_key"`
	Flags   []string `yaml:"flags"`
}

type catalogue struct {
	Permissions []perm              `yaml:"permissions"`
	VendorRoles map[string][]string `yaml:"vendor_roles"`
	LinkScopes  []struct {
		Key string `yaml:"key"`
	} `yaml:"link_scopes"`
}

var methods = []string{"get", "post", "put", "patch", "delete"}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: validate-specs <repo-root>")
		os.Exit(2)
	}
	errs, notes := run(os.Args[1])
	for _, n := range notes {
		fmt.Println("note:", n)
	}
	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, "FAIL:", e)
		}
		os.Exit(1)
	}
	fmt.Println("specs: permission catalogue, realms, callers and vendor-audit markers are consistent")
}

func run(root string) (errs, notes []string) {
	fail := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }

	var cat catalogue
	b, err := os.ReadFile(filepath.Join(root, "common", "permissions.yaml"))
	if err != nil {
		return []string{err.Error()}, nil
	}
	if err := yaml.Unmarshal(b, &cat); err != nil {
		return []string{"permissions.yaml: " + err.Error()}, nil
	}

	byKey := map[string]perm{}
	allowedFlags := map[string]bool{"sensitive": true, "strong_only": true, "owner_grant": true, "support_viewable": true, "support_actable": true}
	for _, p := range cat.Permissions {
		if _, dup := byKey[p.Key]; dup {
			fail("catalogue: duplicate permission %s", p.Key)
		}
		byKey[p.Key] = p
		if p.DescKey == "" || p.Service == "" {
			fail("catalogue: %s needs service and description_key", p.Key)
		}
		if p.Realm != "tenant" && p.Realm != "vendor" && p.Realm != "service" {
			fail("catalogue: %s has unknown realm %q", p.Key, p.Realm)
		}
		if (p.Realm == "vendor") != strings.HasPrefix(p.Key, "admin.") {
			fail("catalogue: %s: admin.* is the vendor realm, and only it", p.Key)
		}
		fl := map[string]bool{}
		for _, f := range p.Flags {
			if !allowedFlags[f] {
				fail("catalogue: %s has unknown flag %s", p.Key, f)
			}
			fl[f] = true
		}
		if fl["strong_only"] && !fl["owner_grant"] {
			fail("catalogue: %s is strong_only but not owner_grant (ADR-0005 A2.4 G2)", p.Key)
		}
		if fl["support_actable"] && (fl["strong_only"] || fl["owner_grant"] || fl["sensitive"]) {
			fail("catalogue: %s is support_actable together with strong_only, owner_grant or sensitive (ADR-0005 A2.5)", p.Key)
		}
		if p.Realm != "tenant" && (fl["support_viewable"] || fl["support_actable"]) {
			fail("catalogue: %s: support flags belong to tenant-realm permissions only", p.Key)
		}
	}
	for role, ps := range cat.VendorRoles {
		for _, k := range ps {
			if p, ok := byKey[k]; !ok || p.Realm != "vendor" {
				fail("vendor_roles.%s: %s is not a vendor-realm permission", role, k)
			}
		}
	}
	for _, s := range cat.LinkScopes {
		if byKey[s.Key].Key != "" {
			fail("link scope %s collides with a permission", s.Key)
		}
	}

	files, _ := filepath.Glob(filepath.Join(root, "openapi", "*", "v1", "openapi.yaml"))
	sort.Strings(files)
	used := map[string]bool{}
	for _, f := range files {
		svc := filepath.Base(filepath.Dir(filepath.Dir(f)))
		raw, err := os.ReadFile(f)
		if err != nil {
			fail("%s", err)
			continue
		}
		var doc struct {
			Paths map[string]map[string]any `yaml:"paths"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			fail("%s: %v", f, err)
			continue
		}
		for path, item := range doc.Paths {
			for _, m := range methods {
				v, ok := item[m]
				if !ok {
					continue
				}
				op, _ := v.(map[string]any)
				id := fmt.Sprintf("%s %s %s", svc, strings.ToUpper(m), path)
				perm, _ := op["x-permission"].(string)
				internal := strings.HasPrefix(path, "/internal/v1/")
				vendorPath := strings.HasPrefix(path, "/internal/v1/vendor/")

				if perm == "" {
					fail("%s: no x-permission", id)
				}
				p, known := byKey[perm]
				if perm != "public" && perm != "authenticated" {
					used[perm] = true
					if !known {
						fail("%s: x-permission %s is not in common/permissions.yaml", id, perm)
					} else {
						switch {
						case svc == "admin" || vendorPath:
							if p.Realm != "vendor" {
								fail("%s: vendor-route operations need an admin.* permission, got %s", id, perm)
							}
						case internal:
							if p.Realm != "service" {
								fail("%s: /internal/v1 operations outside /vendor use a service-realm permission, got %s", id, perm)
							}
						default:
							if p.Realm != "tenant" {
								fail("%s: tenant-facing operations need a tenant-realm permission, got %s", id, perm)
							}
						}
						has := map[string]bool{}
						for _, f := range p.Flags {
							has[f] = true
						}
						if has["support_viewable"] && m != "get" {
							fail("%s: support_viewable permission %s on a write operation", id, perm)
						}
						if su, _ := op["x-step-up"].(bool); su && !has["strong_only"] {
							fail("%s: x-step-up operation needs a strong_only permission, got %s", id, perm)
						}
					}
				}
				if w, ok := op["x-permission-widened-by"].(string); ok {
					used[w] = true
					if _, ok := byKey[w]; !ok {
						fail("%s: x-permission-widened-by %s not in catalogue", id, w)
					}
				}
				if bk, ok := op["x-permission-by-kind"].(map[string]any); ok {
					for _, pv := range bk {
						ps, _ := pv.(string)
						used[ps] = true
						if _, ok := byKey[ps]; !ok {
							fail("%s: x-permission-by-kind %s not in catalogue", id, ps)
						}
					}
				}

				callers, hasCallers := op["x-service-callers"]
				switch {
				case internal && !hasCallers:
					fail("%s: /internal/v1 operation without x-service-callers", id)
				case !internal && hasCallers:
					fail("%s: x-service-callers on a non-internal operation", id)
				case hasCallers:
					if l, _ := callers.([]any); len(l) == 0 {
						fail("%s: x-service-callers is empty", id)
					}
				}

				audit, hasAudit := op["x-vendor-audit"].(string)
				class, _ := op["x-vendor-class"].(string)
				if vendorPath && (!hasAudit || class == "") {
					fail("%s: vendor operation needs x-vendor-class and x-vendor-audit", id)
				}
				if !vendorPath && (hasAudit || class != "") {
					fail("%s: x-vendor-audit and x-vendor-class belong on /internal/v1/vendor operations", id)
				}
				if hasAudit && audit != "none" && audit != "recorded" {
					fail("%s: x-vendor-audit must be none or recorded", id)
				}
				if audit == "none" && class != "directory" {
					fail("%s: x-vendor-audit: none is allowed on directory-class operations only (ADR-0013 V5)", id)
				}
				if class == "directory" && m != "get" {
					fail("%s: a directory-class operation must be a read", id)
				}
				if ff, ok := op["x-feature-flag"].(string); ok && ff != "LINKS_ENABLED" {
					fail("%s: unknown x-feature-flag %s", id, ff)
				}
			}
		}
	}
	var unused []string
	for k := range byKey {
		if !used[k] {
			unused = append(unused, k)
		}
	}
	sort.Strings(unused)
	if len(unused) > 0 {
		notes = append(notes, "catalogue entries not used by any operation yet: "+strings.Join(unused, ", "))
	}
	return errs, notes
}
