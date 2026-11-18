//go:build js && wasm

// Command odrl-builder exposes the ODRL codec to the builder page in
// docs/odrl-builder, compiled to WebAssembly. The page edits a delegation
// record; this renders it through the same codec the org host commits with, so
// the ODRL and the errors shown are the host's own.
//
// Build with `make odrl-builder`.
package main

import (
	"encoding/json"
	"syscall/js"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/delegation"
	"github.com/DIMO-Network/did-directory/pkg/odrl"
)

// constraints is delegation.RoleConstraints with durations in seconds, as the
// wire carries them: a JavaScript number cannot hold a year in nanoseconds.
type constraints struct {
	MaxVehicles       int      `json:"maxVehicles,omitempty"`
	MaxValiditySecs   int64    `json:"maxValiditySeconds,omitempty"`
	MaxDataReachSecs  int64    `json:"maxDataReachSeconds,omitempty"`
	Abilities         []string `json:"abilities,omitempty"`
	AllowRedelegation bool     `json:"allowRedelegation,omitempty"`
	AllowExclusive    bool     `json:"allowExclusive,omitempty"`
	Policy            string   `json:"policy,omitempty"`
}

// form is what the page edits: a record, its uid and the duties it carries.
type form struct {
	delegation.Record
	Constraints *constraints `json:"constraints,omitempty"`
	UID         string       `json:"uid,omitempty"`
	Duties      []odrl.Duty  `json:"duties,omitempty"`
}

func (f *form) record() *delegation.Record {
	rec := f.Record
	if c := f.Constraints; c != nil {
		rec.Constraints = &delegation.RoleConstraints{
			MaxVehicles:       c.MaxVehicles,
			MaxValidity:       time.Duration(c.MaxValiditySecs) * time.Second,
			MaxDataReach:      time.Duration(c.MaxDataReachSecs) * time.Second,
			Abilities:         c.Abilities,
			AllowRedelegation: c.AllowRedelegation,
			AllowExclusive:    c.AllowExclusive,
			Policy:            c.Policy,
		}
	}
	return &rec
}

func toForm(rec *delegation.Record, uid string, duties []odrl.Duty) form {
	f := form{Record: *rec, UID: uid, Duties: duties}
	if c := rec.Constraints; c != nil {
		f.Constraints = &constraints{
			MaxVehicles:       c.MaxVehicles,
			MaxValiditySecs:   int64(c.MaxValidity / time.Second),
			MaxDataReachSecs:  int64(c.MaxDataReach / time.Second),
			Abilities:         c.Abilities,
			AllowRedelegation: c.AllowRedelegation,
			AllowExclusive:    c.AllowExclusive,
			Policy:            c.Policy,
		}
	}
	f.Record.Constraints = nil
	return f
}

// build renders a form as ODRL: {odrl} or {error}.
func build(in string) map[string]any {
	var f form
	if err := json.Unmarshal([]byte(in), &f); err != nil {
		return map[string]any{"error": err.Error()}
	}
	out, err := odrl.Marshal(f.record(), f.UID, f.Duties...)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	return map[string]any{"odrl": string(out)}
}

// parse reads ODRL back into a form: {form} or {error}.
func parse(in string) map[string]any {
	rec, uid, duties, err := odrl.Unmarshal([]byte(in))
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	out, err := json.Marshal(toForm(rec, uid, duties))
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	return map[string]any{"form": string(out)}
}

func classOf(ability string) string {
	switch delegation.ClassOf(ability) {
	case delegation.Live:
		return "live"
	case delegation.Admin:
		return "admin"
	default:
		return "historical"
	}
}

func wrap(fn func(string) map[string]any) js.Func {
	return js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) != 1 {
			return map[string]any{"error": "expected one argument"}
		}
		return fn(args[0].String())
	})
}

func main() {
	js.Global().Set("odrlBuilder", map[string]any{
		"build": wrap(build),
		"parse": wrap(parse),
		"classOf": js.FuncOf(func(_ js.Value, args []js.Value) any {
			return classOf(args[0].String())
		}),
	})
	js.Global().Call("dispatchEvent", js.Global().Get("Event").New("odrl-builder-ready"))
	select {}
}
