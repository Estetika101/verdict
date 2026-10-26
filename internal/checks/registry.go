// Package checks is the registry of built-in checks. Built-ins register through
// the same model.Check interface a WASM plugin is adapted to — there is no
// privileged built-in path in the registry (v0.4 §2c).
package checks

import (
	"github.com/Estetika101/verdict/internal/checks/geo"
	"github.com/Estetika101/verdict/internal/checks/links"
	"github.com/Estetika101/verdict/internal/checks/security"
	"github.com/Estetika101/verdict/internal/checks/seo"
	"github.com/Estetika101/verdict/internal/model"
)

// Builtins returns every compiled-in check. The caller filters by config
// (module or check-ID enable) before running them.
func Builtins() []model.Check {
	all := security.All()
	all = append(all, links.New())
	all = append(all, seo.All()...)
	all = append(all, geo.All()...)
	return all
}
