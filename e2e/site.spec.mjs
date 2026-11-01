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
    const socialLinks = [
      ['Juss & Co. on Instagram', 'https://www.instagram.com/jussnco/'],
      ['Juss Ray on YouTube', 'https://www.youtube.com/channel/UCpEsqUi3uDpiNonJuu1hOKQ'],
      ['Juss Rayy on LinkedIn', 'https://www.linkedin.com/in/juss-rayy-13ba691a1'],
    ];
    await expect(page.locator('.socials a')).toHaveCount(socialLinks.length);
    for (const [name, href] of socialLinks) {
      const link = page.getByRole('link', { name, exact: true });
      await expect(link).toHaveAttribute('href', href);
      await expect(link).toHaveAttribute('target', '_blank');
      await expect(link).toHaveAttribute('rel', 'noopener noreferrer');
    }
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

test('Model One About is findable, distinct, honest and readable on mobile', async ({ page }) => {
  for (const width of [320, 390, 1280]) {
    await page.setViewportSize({ width, height: 800 });
    const response = await page.goto('/about.html');
    expect(response?.status()).toBe(200);
    await expect(page).toHaveTitle('About Juss Protect Me | Personal Cyber Safety | Juss & Co.');
    await expect(page.getByRole('heading', { level: 1, name: /About Juss Protect Me: people-first online safety/ })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Who is Juss Protect Me for?' })).toBeVisible();
    await expect(page.getByText(/not a live device scan, antivirus service/i)).toBeVisible();
    await expect(page.locator('link[rel="canonical"]')).toHaveAttribute('href', 'https://protect.jussco.company/about.html');
    await expect(page.locator('meta[name="description"]')).toHaveAttribute('content', /personal cybersecurity project/);
    const data = JSON.parse(await page.locator('script[type="application/ld+json"]').textContent());
    expect(data['@graph'].find((entry) => entry['@type'] === 'AboutPage')?.mainEntity?.['@id']).toBe('https://protect.jussco.company/#product');
    await expect(page.getByRole('link', { name: /Juss Protect Me 2 \(Model Two\)/ })).toHaveAttribute('href', 'https://protect2.jussco.company/about.html');
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1);
    expect(overflow).toBe(false);
    await page.screenshot({ path: `test-results/model-one-about-${width}.png` });
  }
});


test('Model One product catalog navigates from home and stays honest on mobile', async ({ page }) => {
  for (const width of [320, 390, 1280]) {
    await page.setViewportSize({ width, height: 820 });
    await page.goto('/');
    await page.getByRole('navigation', { name: 'Primary navigation' }).getByRole('link', { name: 'Products' }).click();
    await expect(page).toHaveURL(/\/products\.html$/);
    await expect(page.locator('.cards .card')).toHaveCount(4);
    for (const title of ['Guided Safety Checkup', 'Device & Browser Safety', 'Identity & Scam Safety', 'Family Privacy & Recovery']) {
      await expect(page.getByRole('heading', { name: title })).toBeVisible();
    }
    await expect(page.getByText(/Live device scanning is not active/)).toBeVisible();
    await expect(page.getByRole('link', { name: /Open the checkup preview/ })).toHaveAttribute('href', '/app.html');
    await expect(page.locator('link[rel="canonical"]')).toHaveAttribute('href', 'https://protect.jussco.company/products.html');
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(1);
    await page.screenshot({ path: `test-results/model-one-products-${width}.png` });
  }
});

test('all four benefit cards open their matching checkup group on mobile and desktop', async ({ page }) => {
  const cards = [
    ['Device Safety', 'device-safety'],
    ['Identity Protection', 'identity-protection'],
    ['Everyday Safety', 'everyday-safety'],
    ['Privacy First', 'privacy-first'],
  ];
  for (const width of [320, 390, 1280]) {
    await page.setViewportSize({ width, height: 820 });
    for (const [label, slug] of cards) {
      await page.goto('/');
      const card = page.getByRole('link', { name: `Open ${label} guided checkup` });
      await expect(card).toHaveAttribute('href', `/app.html#${slug}`);
      await card.click();
      await expect(page).toHaveURL(new RegExp(`/app\\.html#${slug}$`));
      const target = page.locator(`#${slug}`);
      await expect(target).toBeVisible();
      await expect(target.getByRole('heading', { name: label })).toBeVisible();
      const onscreen = await target.evaluate(el => {
        const bounds = el.getBoundingClientRect();
        return bounds.top < window.innerHeight && bounds.bottom > 0;
      });
      expect(onscreen).toBe(true);
      await expect(page.getByText(/does not scan your device/i)).toBeVisible();
    }
  }
});
