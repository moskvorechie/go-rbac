package rbac

import (
	"github.com/casbin/casbin"
	"github.com/casbin/gorm-adapter"
	"github.com/vmpartner/go-pgdb"
)

var RBAC *casbin.Enforcer

func init() {
	RBAC = New()
}

func New() *casbin.Enforcer {
	if RBAC != nil {
		return RBAC
	}
	a := gormadapter.NewAdapter("postgres", db.GetLInk(), true)
	RBAC = casbin.NewEnforcer("rbac_model.conf", a)

	return RBAC
}

func Check(email string, rule string, perm string) bool {
	if !RBAC.Enforce(email, rule, perm) {
		return false
	}
	return true
}
