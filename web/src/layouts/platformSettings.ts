import { Permission } from '../auth/permissions';

// Shared by the settings center and sidebar; permissions stay platform-scoped.
export const platformSettingsEntries = [
  { path: '/platform/engines', name: '配置管理', description: '管理引擎连接、数据源凭据、运行策略和连接检测。', permission: Permission.AdminManage },
  { path: '/platform/users', name: '用户管理', description: '管理账号与平台角色，查看项目授权。', permission: Permission.UserRead },
  { path: '/platform/roles', name: '权限管理', description: '查看角色权限矩阵；平台角色在用户管理中分配。', permission: Permission.UserRead }
];
