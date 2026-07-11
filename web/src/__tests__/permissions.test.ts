import { describe, expect, it } from 'vitest';

import { Permission, hasPermission, rolePermissions } from '../auth/permissions';

describe('permissions', () => {
  it('keeps viewer read-only and without export permission', () => {
    expect(hasPermission(rolePermissions.viewer, Permission.AssetRead)).toBe(true);
    expect(hasPermission(rolePermissions.viewer, Permission.AssetWrite)).toBe(false);
    expect(hasPermission(rolePermissions.viewer, Permission.ReportExport)).toBe(false);
  });

  it('grants report export to security admin', () => {
    expect(hasPermission(rolePermissions.security_admin, Permission.ReportExport)).toBe(true);
    expect(hasPermission(rolePermissions.security_admin, Permission.AdminManage)).toBe(false);
  });

  it('grants user management access to system and security admins by default', () => {
    expect(hasPermission(rolePermissions.system_admin, Permission.UserRead)).toBe(true);
    expect(hasPermission(rolePermissions.system_admin, Permission.UserWrite)).toBe(true);
    expect(hasPermission(rolePermissions.system_admin, Permission.UserCredentialReset)).toBe(true);
    expect(hasPermission(rolePermissions.system_admin, Permission.UserRoleWrite)).toBe(true);
    expect(hasPermission(rolePermissions.security_admin, Permission.UserRead)).toBe(false);
    expect(hasPermission(rolePermissions.security_admin, Permission.UserWrite)).toBe(false);
    expect(hasPermission(rolePermissions.security_admin, Permission.UserCredentialReset)).toBe(false);
    expect(hasPermission(rolePermissions.security_admin, Permission.UserRoleWrite)).toBe(false);
  });
});
