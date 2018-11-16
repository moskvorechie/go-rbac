package rbac

import (
	"github.com/casbin/casbin"
	"github.com/casbin/gorm-adapter"
	"github.com/vmpartner/go-pgdb"
)

var RBAC *casbin.Enforcer

func New() *casbin.Enforcer {
	if RBAC != nil {
		return RBAC
	}
	a := gormadapter.NewAdapter("postgres", pgdb.GetLInk(), true)
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
	if !RBAC.Enforce(email, rule, perm) {
		return false
	}
	return true
}
