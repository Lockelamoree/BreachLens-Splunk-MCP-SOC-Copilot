import { expect, test } from "@playwright/test";

const alert = {
  alert_id: "BLS-2026-001",
  title: "Impossible travel followed by suspicious cloud API activity",
  severity: "critical",
  severity_score: 96,
  status: "new",
  time: "2026-05-28T09:24:18Z",
  user: "maria.chen",
  src_ip: "203.0.113.45",
  host: "LAPTOP-MCHEN",
  asset: "okta/aws",
  description: "Synthetic breach chain",
  recommended_objective: "Determine account takeover and blast radius."
};

const investigation = {
  investigation_id: "INV-DEMO",
  alert,
  status: "complete",
  summary: "Evidence supports a high-confidence compromise chain.",
  confidence: "high",
  objective: alert.recommended_objective,
  evidence: [
    {
      id: "EV-001",
      query_id: "Q-identity",
      time: "2026-05-28T09:12:04Z",
      source: "breachlens:auth",
      title: "Auth failure for alex.rivera",
      summary: "Password spray failure.",
      fields: {}
    },
    {
      id: "EV-002",
      query_id: "Q-proxy",
      time: "2026-05-28T09:49:18Z",
      source: "breachlens:proxy",
      title: "Large upload",
      summary: "High-volume file-sharing transfer.",
      fields: {}
    }
  ],
  timeline: [
    {
      time: "2026-05-28T09:12:04Z",
      phase: "Initial access",
      title: "Password spray targets multiple users",
      narrative: "203.0.113.45 generated repeated failed logins.",
      evidence_ids: ["EV-001"]
    },
    {
      time: "2026-05-28T09:49:18Z",
      phase: "Exfiltration",
      title: "Large outbound transfer to file-sharing service",
      narrative: "The host sent high-volume outbound PUT requests.",
      evidence_ids: ["EV-002"]
    }
  ],
  mitre: [
    {
      technique_id: "T1110.003",
      technique: "Password Spraying",
      tactic: "Credential Access",
      rationale: "Multiple failed logins.",
      evidence_ids: ["EV-001"]
    }
  ],
  response_actions: [
    {
      priority: "P0",
      owner: "Identity",
      action: "Disable the user and revoke sessions.",
      evidence_ids: ["EV-001"]
    }
  ],
  spl_transcript: [
    {
      query_id: "Q-identity",
      purpose: "Pivot across authentication activity.",
      spl: "search index=breachlens sourcetype=breachlens:auth",
      result_count: 10,
      tool: "splunk_run_query"
    }
  ],
  warnings: []
};

test("analyst can run an investigation and generate detections", async ({ page }) => {
  await page.route("**/api/alerts", async (route) => {
    await route.fulfill({ json: { alerts: [alert] } });
  });
  await page.route("**/api/investigations", async (route) => {
    await route.fulfill({ json: investigation });
  });
  await page.route("**/api/detections", async (route) => {
    await route.fulfill({
      json: {
        investigation_id: "INV-DEMO",
        detections: [
          {
            detection_id: "DET-password-spray-success",
            title: "Password spray followed by successful authentication",
            severity: "high",
            spl: "`breachlens_index` sourcetype=breachlens:auth",
            sigma: "title: Password Spray",
            evidence_ids: ["EV-001"]
          }
        ]
      }
    });
  });

  await page.goto("/");
  await expect(page.getByRole("heading", { name: "BreachLens" })).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Impossible travel followed by suspicious cloud API activity" })
  ).toBeVisible();

  await page.getByRole("button", { name: "Investigate" }).click();
  await expect(page.getByText("Incident Timeline")).toBeVisible();
  await expect(page.getByText("Impact Meter")).toBeVisible();
  await expect(page.getByText("Password spray targets multiple users")).toBeVisible();
  await expect(page.getByText("T1110.003")).toBeVisible();
  await expect(page.getByRole("button", { name: "Ledger" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Report" })).toBeVisible();
  await page.getByRole("button", { name: "EV-001" }).click();
  await expect(page.getByLabel("Evidence details")).toBeVisible();
  await page.locator('button[title="Close evidence details"]').click();

  await page.locator(".topbar-actions").getByRole("button", { name: "Detections" }).click();
  await expect(page.getByText("Password spray followed by successful authentication")).toBeVisible();
});
