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
      fields: {},
      splunk_url: "http://localhost:18000/en-US/app/search/search?q=search%20index%3Dbreachlens"
    },
    {
      id: "EV-002",
      query_id: "Q-proxy",
      time: "2026-05-28T09:49:18Z",
      source: "breachlens:proxy",
      title: "Large upload",
      summary: "High-volume file-sharing transfer.",
      fields: {},
      splunk_url: "http://localhost:18000/en-US/app/search/search?q=search%20index%3Dbreachlens"
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
  analyst_note: {
    provider: "ollama",
    status: "confirmed_compromise",
    narrative: "Evidence supports suspicious authentication followed by a large outbound transfer.",
    evidence_ids: ["EV-001", "EV-002"]
  },
  spl_transcript: [
    {
      query_id: "CTX-indexes",
      purpose: "Confirm Splunk index access.",
      spl: "splunk_get_indexes()",
      result_count: 1,
      tool: "splunk_get_indexes"
    },
    {
      query_id: "CTX-metadata",
      purpose: "Inspect indexed sourcetypes and metadata.",
      spl: "splunk_get_metadata()",
      result_count: 5,
      tool: "splunk_get_metadata"
    },
    {
      query_id: "CTX-knowledge",
      purpose: "Inspect saved searches and knowledge objects.",
      spl: "splunk_get_knowledge_objects()",
      result_count: 2,
      tool: "splunk_get_knowledge_objects"
    },
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
  await page.route("**/health", async (route) => {
    await route.fulfill({
      json: {
        status: "ok",
        mode: "mcp",
        splunk_client: "splunk_mcp",
        splunk_index: "breachlens",
        splunk_ui_url: "http://127.0.0.1:18000",
        splunk_evidence_links_enabled: true,
        ai_provider: "ollama",
        ai_model: "hf.co/LockeLamora2077/NiNa:latest",
        ai_model_url: "https://huggingface.co/LockeLamora2077/NiNa",
        investigations_in_memory: 0
      }
    });
  });
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
  const proofStrip = page.getByLabel("Live MCP proof strip");
  await expect(proofStrip).toBeVisible();
  await expect(proofStrip.getByText("Splunk MCP live")).toBeVisible();
  await expect(proofStrip.getByText("mcp", { exact: true })).toBeVisible();
  await expect(proofStrip.getByText("splunk_mcp", { exact: true })).toBeVisible();
  await expect(proofStrip.getByText("NiNa:latest")).toBeVisible();

  await page.getByRole("button", { name: "Investigate" }).click();
  await expect(proofStrip.getByText("4/4 observed")).toBeVisible();
  await expect(proofStrip.getByText("2 items")).toBeVisible();
  await expect(proofStrip.getByText("splunk_get_indexes")).toBeVisible();
  await expect(proofStrip.getByText("splunk_get_metadata")).toBeVisible();
  await expect(proofStrip.getByText("splunk_get_knowledge_objects")).toBeVisible();
  await expect(proofStrip.getByText("splunk_run_query")).toBeVisible();
  await expect(page.getByText("Incident Timeline")).toBeVisible();
  await expect(page.getByText("Impact Meter")).toBeVisible();
  await expect(page.getByText("Password spray targets multiple users")).toBeVisible();
  await expect(page.getByText("T1110.003")).toBeVisible();
  await expect(page.getByRole("button", { name: "Ledger" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Report" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Splunk" })).toHaveCount(2);
  await page.locator(".timeline").getByRole("button", { name: "EV-001" }).click();
  await expect(page.getByLabel("Evidence details")).toBeVisible();
  await expect(page.getByRole("link", { name: "Open source event in Splunk" })).toBeVisible();
  await page.locator('button[title="Close evidence details"]').click();

  await page.locator(".topbar-actions").getByRole("button", { name: "Detections" }).click();
  await expect(page.getByText("Password spray followed by successful authentication")).toBeVisible();
});
