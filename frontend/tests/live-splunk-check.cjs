const { chromium } = require("@playwright/test");

const appUrl = process.env.BREACHLENS_APP_URL || "http://127.0.0.1:5173/";
const expectedMode = process.env.EXPECTED_BREACHLENS_MODE || "mcp";
const expectedClient = process.env.EXPECTED_SPLUNK_CLIENT || "splunk_mcp";

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1440, height: 1200 } });
  const errors = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") {
      errors.push(msg.text());
    }
  });

  await page.goto(appUrl, { waitUntil: "networkidle" });
  await page.getByText(expectedMode, { exact: true }).waitFor({ timeout: 10000 });
  await page.getByText(expectedClient, { exact: true }).waitFor({ timeout: 10000 });
  await page.getByRole("button", { name: "Investigate" }).click();
  await page.getByText("Impact Meter").waitFor({ timeout: 15000 });
  await page.getByText("Large outbound transfer to file-sharing service").waitFor({ timeout: 15000 });
  await page.locator(".timeline").getByRole("button").first().click();
  await page.getByLabel("Evidence details").waitFor({ timeout: 10000 });
  await page.locator('button[title="Close evidence details"]').click();

  await page.getByRole("button", { name: "SPL" }).click();
  await waitForTranscriptTool(page, "splunk_get_indexes");
  await waitForTranscriptTool(page, "splunk_get_metadata");
  await waitForTranscriptTool(page, "splunk_get_knowledge_objects");
  await waitForTranscriptTool(page, "splunk_run_query");

  const ledgerDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "Ledger" }).click();
  const ledger = await ledgerDownload;

  const reportDownload = page.waitForEvent("download");
  await page.getByRole("button", { name: "Report" }).click();
  const report = await reportDownload;

  await page.locator(".topbar-actions").getByRole("button", { name: "Detections" }).click();
  await page.getByText("Password spray followed by successful authentication").waitFor({ timeout: 15000 });
  await page.screenshot({ path: "../docs/breachlens-ui-real-splunk.png", fullPage: true });

  const metrics = await page.locator(".metric").allTextContents();
  console.log(
    JSON.stringify({
      expectedMode,
      expectedClient,
      consoleErrors: errors,
      metrics,
      mcpProof: [
        "splunk_get_indexes",
        "splunk_get_metadata",
        "splunk_get_knowledge_objects",
        "splunk_run_query",
      ],
      ledger: ledger.suggestedFilename(),
      report: report.suggestedFilename(),
      screenshot: "docs/breachlens-ui-real-splunk.png",
    })
  );
  await browser.close();
})().catch((error) => {
  console.error(error);
  process.exit(1);
});

async function waitForTranscriptTool(page, toolName) {
  await page.locator(".query-card").filter({ hasText: toolName }).first().waitFor({ timeout: 15000 });
}
