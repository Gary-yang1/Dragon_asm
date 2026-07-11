import { Navigate, Route, Routes } from 'react-router-dom';

import { RequireAuth } from './auth/RequireAuth';
import { RequirePermission } from './auth/RequirePermission';
import { Permission } from './auth/permissions';
import { AppLayout } from './layouts/AppLayout';
import { AssetsPage } from './pages/assets/AssetsPage';
import { DashboardPage } from './pages/DashboardPage';
import { DiscoveryPage } from './pages/discovery/DiscoveryPage';
import { ForbiddenPage } from './pages/ForbiddenPage';
import { LoginPage } from './pages/LoginPage';
import { ChangePasswordPage } from './pages/ChangePasswordPage';
import { NotFoundPage } from './pages/NotFoundPage';
import { ReportsPage } from './pages/reports/ReportsPage';
import { PlatformUsersPage } from './pages/admin/PlatformUsersPage';
import { RolePermissionsPage } from './pages/admin/RolePermissionsPage';
import { RisksPage } from './pages/risks/RisksPage';
import { SettingsPage } from './pages/settings/SettingsPage';
import { TicketsPage } from './pages/tickets/TicketsPage';
import { ProjectsPage } from './pages/projects/ProjectsPage';
import { ProjectProfilePage } from './pages/projects/ProjectProfilePage';
import { ProjectCreatePage } from './pages/projects/ProjectCreatePage';
import { WorkItemsPage } from './pages/workspace/WorkItemsPage';
import { WorkspacePage } from './pages/workspace/WorkspacePage';
import { LandingRedirect, LegacyProjectRedirect, ProjectWorkspaceProvider } from './projects/ProjectContext';

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/change-password" element={<RequireAuth><ChangePasswordPage /></RequireAuth>} />
      <Route
        path="/"
        element={
          <RequireAuth>
            <ProjectWorkspaceProvider>
              <AppLayout />
            </ProjectWorkspaceProvider>
          </RequireAuth>
        }
      >
        <Route index element={<LandingRedirect />} />
        <Route path="workspace" element={<WorkspacePage />} />
        <Route path="work-items" element={<WorkItemsPage />} />
        <Route path="projects" element={<ProjectsPage />} />
        <Route
          path="projects/new"
          element={
            <RequirePermission permission={Permission.ProjectCreate}>
              <ProjectCreatePage />
            </RequirePermission>
          }
        />
        <Route path="projects/:projectId" element={<Navigate to="overview" replace />} />
        <Route
          path="projects/:projectId/overview"
          element={
            <RequirePermission permission={Permission.ReportRead}>
              <DashboardPage />
            </RequirePermission>
          }
        />
        <Route
          path="projects/:projectId/profile"
          element={
            <RequirePermission permission={Permission.ProjectRead}>
              <ProjectProfilePage />
            </RequirePermission>
          }
        />
        <Route
          path="projects/:projectId/assets"
          element={
            <RequirePermission permission={Permission.AssetRead}>
              <AssetsPage />
            </RequirePermission>
          }
        />
        <Route
          path="projects/:projectId/discovery"
          element={
            <RequirePermission permission={Permission.DiscoveryRead}>
              <DiscoveryPage />
            </RequirePermission>
          }
        />
        <Route
          path="projects/:projectId/risks"
          element={
            <RequirePermission permission={Permission.RiskRead}>
              <RisksPage />
            </RequirePermission>
          }
        />
        <Route
          path="projects/:projectId/tickets"
          element={
            <RequirePermission permission={Permission.TicketRead}>
              <TicketsPage />
            </RequirePermission>
          }
        />
        <Route
          path="projects/:projectId/reports"
          element={
            <RequirePermission permission={Permission.ReportRead}>
              <ReportsPage />
            </RequirePermission>
          }
        />
        <Route
          path="projects/:projectId/settings"
          element={
            <RequirePermission permission={Permission.AdminManage}>
              <SettingsPage />
            </RequirePermission>
          }
        />
        <Route
          path="platform"
          element={
            <RequirePermission permission={Permission.UserRead}>
              <Navigate to="/platform/users" replace />
            </RequirePermission>
          }
        />
        <Route
          path="platform/users"
          element={
            <RequirePermission permission={Permission.UserRead}>
              <PlatformUsersPage />
            </RequirePermission>
          }
        />
        <Route
          path="platform/roles"
          element={
            <RequirePermission permission={Permission.UserRead}>
              <RolePermissionsPage />
            </RequirePermission>
          }
        />
        <Route path="dashboard" element={<LegacyProjectRedirect page="overview" />} />
        <Route path="assets" element={<LegacyProjectRedirect page="assets" />} />
        <Route path="discovery" element={<LegacyProjectRedirect page="discovery" />} />
        <Route path="risks" element={<LegacyProjectRedirect page="risks" />} />
        <Route path="tickets" element={<LegacyProjectRedirect page="tickets" />} />
        <Route path="reports" element={<LegacyProjectRedirect page="reports" />} />
        <Route
          path="settings"
          element={
            <RequirePermission permission={Permission.AdminManage}>
              <LegacyProjectRedirect page="settings" />
            </RequirePermission>
          }
        />
        <Route
          path="settings/users"
          element={
            <RequirePermission permission={Permission.UserRead}>
              <Navigate to="/platform/users" replace />
            </RequirePermission>
          }
        />
        <Route
          path="settings/roles"
          element={
            <RequirePermission permission={Permission.UserRead}>
              <Navigate to="/platform/roles" replace />
            </RequirePermission>
          }
        />
        <Route path="403" element={<ForbiddenPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
