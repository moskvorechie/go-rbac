package rbac

import (
	"github.com/casbin/casbin"
	"github.com/casbin/gorm-adapter"
)

var RBAC *casbin.Enforcer
var dbLink string

func New(dbSrc string) *casbin.Enforcer {
	dbLink = dbSrc
	if RBAC != nil {
		return RBAC
	}
	a := gormadapter.NewAdapter("postgres", dbLink, true)
	p := `
		[request_definition]
		r = sub, obj, act
		
		[policy_definition]
		p = sub, obj, act
		
		[role_definition]
		g = _, _
		
		[policy_effect]
		e = some(where (p.eft == allow))
		
		[matchers]
		m = (g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act) || g(r.sub, "admin")
	`
	RBAC = casbin.NewEnforcer(casbin.NewModel(p), a)

	return RBAC
}

func Check(email string, rule string, perm string) bool {
	if RBAC == nil {
		RBAC = New(dbLink)
	}
	if !RBAC.Enforce(email, rule, perm) {
		return false
	}
	return true
}
