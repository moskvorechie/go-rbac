package rbac

import (
	"github.com/casbin/casbin"
	"gitlab.com/vitams/qvard/modules/db"
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
	RBAC = casbin.NewEnforcer("./modules/rbac/rbac_model.conf", a)

	return RBAC
}

func Check(email string, rule string, perm string) bool {
	if !RBAC.Enforce(email, rule, perm) {
		return false
	}
	return true
}

func GetPermissionsForUser(email string) [][]string {
	return RBAC.GetPermissionsForUser(email)
}

func GetRolesForUser(email string) []string {
	return RBAC.GetRolesForUser(email)
}
