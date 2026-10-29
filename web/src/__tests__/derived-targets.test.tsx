import { App as AntApp } from "antd";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Permission } from "../auth/permissions";
import { DerivedTargets } from "../pages/discovery/DerivedTargets";
import { server } from "../test/server";
import type { DerivedTargetPage } from "../api/discovery";

const grants = vi.hoisted(() => new Set<string>());
vi.mock("../auth/usePermission", () => ({
  usePermission: () => ({
    can: (permission: string) => grants.has(permission),
  }),
}));
const fingerprint = "a".repeat(64);
const template = {
  id: 80,
  project_id: 1,
  scope_id: 2,
  task_type: "dns",
  name: "接续发现",
  enabled: true,
  config: {
    targets: [{ type: "domain", value: "api.example.com" }],
    options: {},
    inheritance: { source_run_id: 10, parent_scope_id: 2, evidence: [] },
  },
};
let page: DerivedTargetPage;
function setup(onCreated = vi.fn(), onScopeUpdated = vi.fn()) {
  const view = render(
    <AntApp>
      <DerivedTargets
        projectId={1}
        runId={10}
        onClose={vi.fn()}
        onCreated={onCreated}
        onScopeUpdated={onScopeUpdated}
      />
    </AntApp>,
  );
  return { ...view, onCreated, onScopeUpdated };
}
beforeEach(() => {
  grants.clear();
  [
    Permission.DiscoveryRun,
    Permission.ScopeWrite,
    Permission.ScopeRead,
    Permission.AssetRead,
  ].forEach((permission) => grants.add(permission));
  page = {
    source_run_id: 10,
    parent_scope_id: 2,
    parent_scope_name: "根域与自有网段",
    scope_fingerprint: fingerprint,
    valid_until: "2099-01-01T00:00:00Z",
    parent_active: true,
    source_complete: true,
    next_cursor: 0,
    items: [
      {
        observation_id: 1,
        target_type: "domain",
        value: "api.example.com",
        status: "inherited",
        reason: "父授权包含子域名",
        provider: "fixture",
        observed_at: "2026-09-14T00:00:00Z",
        evidence_hash: fingerprint,
      },
      {
        observation_id: 2,
        target_type: "ip",
        value: "8.8.8.8",
        status: "inherited",
        reason: "已在授权网段内",
        provider: "fixture",
        observed_at: "2026-09-14T00:00:00Z",
        evidence_hash: fingerprint,
      },
      {
        observation_id: 3,
        target_type: "ip",
        value: "1.1.1.1",
        status: "pending",
        reason: "需确认",
        provider: "fixture",
        observed_at: "2026-09-14T00:00:00Z",
        evidence_hash: fingerprint,
      },
      {
        observation_id: 4,
        target_type: "domain",
        value: "excluded.example.com",
        status: "excluded",
        reason: "排除规则",
        provider: "fixture",
        observed_at: "2026-09-14T00:00:00Z",
        evidence_hash: fingerprint,
      },
    ],
  };
  server.use(
    http.get("/api/v1/projects/1/discovery/runs/10/derived-targets", () =>
      HttpResponse.json({ data: page }),
    ),
  );
});
describe("DerivedTargets", () => {
  it("automatically selects only covered targets compatible with the chosen next step", async () => {
    let body: unknown;
    server.use(
      http.post(
        "/api/v1/projects/1/discovery/runs/10/continuations",
        async ({ request }) => {
          body = await request.json();
          return HttpResponse.json({ data: template });
        },
      ),
    );
    const { onCreated } = setup();
    await screen.findByText("api.example.com");
    const create = await screen.findByRole("button", {
      name: "生成接续配置（1）",
    });
    expect(
      within(screen.getByRole("row", { name: /8.8.8.8/ })).getByRole(
        "checkbox",
      ),
    ).toBeDisabled();
    await userEvent.click(create);
    await waitFor(() => expect(onCreated).toHaveBeenCalledWith(template));
    expect(body).toEqual({
      task_type: "dns",
      observation_ids: [1],
      scope_fingerprint: fingerprint,
    });
  });
  it("requires explicit checked confirmation to add pending IPs and refreshes inherited status", async () => {
    let body: unknown;
    server.use(
      http.post(
        "/api/v1/projects/1/discovery/runs/10/derived-targets/authorize",
        async ({ request }) => {
          body = await request.json();
          page = {
            ...page,
            scope_fingerprint: "b".repeat(64),
            items: page.items.map((item) =>
              item.observation_id === 3
                ? { ...item, status: "inherited" }
                : item,
            ),
          };
          return HttpResponse.json({ data: { id: 2 } });
        },
      ),
    );
    const { onScopeUpdated } = setup();
    await screen.findByText("api.example.com");
    await userEvent.click(screen.getByText("待确认 1"));
    await userEvent.click(
      within(await screen.findByRole("row", { name: /1.1.1.1/ })).getByRole(
        "checkbox",
      ),
    );
    await userEvent.click(
      screen.getByRole("button", { name: "批量确认授权（1）" }),
    );
    const confirm = await screen.findByRole("button", {
      name: "确认加入父授权",
    });
    expect(confirm).toBeDisabled();
    expect(body).toBeUndefined();
    await userEvent.click(
      screen.getByRole("checkbox", { name: "我已核实并有权授权这些目标" }),
    );
    await userEvent.click(confirm);
    await waitFor(() => expect(onScopeUpdated).toHaveBeenCalledOnce());
    expect(body).toMatchObject({
      observation_ids: [3],
      scope_fingerprint: fingerprint,
    });
    expect(await screen.findByText("已继承 3")).toBeInTheDocument();
  });
  it("does not expose scope expansion actions to operators without scope write permission", async () => {
    grants.delete(Permission.ScopeWrite);
    setup();
    await screen.findByText("api.example.com");
    await userEvent.click(screen.getByText("待确认 1"));
    expect(
      await screen.findByText("请有授权管理权限的项目负责人确认这些目标。"),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /批量确认授权/ }),
    ).not.toBeInTheDocument();
  });
  it("keeps a changed-scope error actionable and does not hand off a failed snapshot", async () => {
    server.use(
      http.post("/api/v1/projects/1/discovery/runs/10/continuations", () =>
        HttpResponse.json(
          {
            error: {
              code: "DISCOVERY_PARENT_SCOPE_CHANGED",
              message: "父授权已变化，请刷新目标后重新确认",
            },
          },
          { status: 409 },
        ),
      ),
    );
    const { onCreated } = setup();
    await screen.findByText("api.example.com");
    await userEvent.click(
      await screen.findByRole("button", { name: "生成接续配置（1）" }),
    );
    expect(
      await screen.findByText("父授权已变化，请刷新目标后重新确认"),
    ).toBeInTheDocument();
    expect(onCreated).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "刷新目标" })).toBeEnabled();
  });
  it("blocks continuation when the parent has expired or been disabled", async () => {
    page.parent_active = false;
    setup();
    await screen.findByText("父授权当前不可用");
    expect(
      await screen.findByRole("button", { name: "生成接续配置（1）" }),
    ).toBeDisabled();
  });
});
