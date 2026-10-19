import { test, expect } from '../fixtures';

for (const legal of [
  { label: 'Imprint', canonical: '/imprint', alias: '/impressum', target: 'https://legal.example.test/imprint' },
  { label: 'Privacy Notice', canonical: '/privacy', alias: '/datenschutz', target: 'https://legal.example.test/privacy' },
]) {
  test(`${legal.label}: logged-out link and canonical redirect`, async ({ page, context }) => {
    await context.route('https://legal.example.test/**', route => route.fulfill({
      contentType: 'text/html', body: '<h1>Company legal page</h1>',
    }));
    await page.goto('/login');
    const link = page.getByRole('link', { name: legal.label, exact: true });
    await expect(link).toHaveAttribute('href', legal.alias);
    const popupPromise = context.waitForEvent('page');
    await link.click();
    const popup = await popupPromise;
    await expect(popup).toHaveURL(legal.target);
    await expect(popup.getByRole('heading', { name: 'Company legal page' })).toBeVisible();
    await popup.close();
    await page.goto(legal.canonical);
    await expect(page).toHaveURL(legal.target);
  });
}
