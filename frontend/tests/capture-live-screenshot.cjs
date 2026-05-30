const { chromium } = require("@playwright/test");

const appUrl = process.env.BREACHLENS_APP_URL || "http://127.0.0.1:5173/";

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  await page.goto(appUrl, { waitUntil: "networkidle" });
  await page.getByLabel("Live MCP proof strip").waitFor({ timeout: 10000 });
  await page.getByText("Splunk REST live").waitFor({ timeout: 10000 });
  await page.getByRole("link", { name: "NiNa:latest" }).waitFor({ timeout: 10000 });
  await page.getByRole("button", { name: "Investigate" }).click();
  await page.getByLabel("AI claim checks").waitFor({ timeout: 30000 });
  await page.screenshot({ path: "../docs/breachlens-ui-real-splunk.png", fullPage: true });
  await browser.close();
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
