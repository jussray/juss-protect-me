import { test, expect } from '@playwright/test';

test('Model One desktop and phones preserve distinct branding, layout and closed enrollment', async ({ page }) => {
  for (const [width, height] of [[320, 740], [390, 844], [1280, 800]]) {
    await page.setViewportSize({ width, height });
    const home = await page.goto('/');
    expect(home?.status()).toBe(200);
    await expect(page).toHaveTitle('Juss Protect Me | Juss & Co.');
    await expect(page.locator('#hero-title')).toBeVisible();
    await expect(page.locator('.hero-portrait')).toBeVisible();
    await expect(page.locator('.feature-card')).toHaveCount(4);
    await expect(page.getByRole('heading', { name: 'Device Safety' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Privacy First' })).toBeVisible();
    await expect(page.getByRole('heading', { name: /AI Agent Security for What Comes Next/ })).toHaveCount(0);
    const sizes = await page.evaluate(() => ({
      documentWidth: document.documentElement.scrollWidth,
      viewportWidth: document.documentElement.clientWidth,
    }));
    expect(sizes.documentWidth).toBeLessThanOrEqual(sizes.viewportWidth + 1);
    const join = page.getByRole('link', { name: /Join Early Access/ });
    await expect(join).toHaveAttribute('href', '/checkout');
    await page.screenshot({ path: `test-results/model-one-width-${width}.png` });
    await join.click();
    await expect(page).toHaveURL((url) => url.pathname === '/checkout');
    await expect(page.getByRole('heading', { name: 'Enrollment opens at launch' })).toBeVisible();
  }
});

test('Model One mobile checkup preview explains it is not an antivirus scan', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const preview = await page.goto('/app.html');
  expect(preview?.status()).toBe(200);
  await expect(page.getByRole('heading', { name: /Your Protect checkup/ })).toBeVisible();
  await expect(page.getByText(/does not scan your device/i)).toBeVisible();
  await page.screenshot({ path: 'test-results/model-one-checkup-mobile.png' });
});
