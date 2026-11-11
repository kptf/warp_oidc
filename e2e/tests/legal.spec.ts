import { test, expect } from '../fixtures';

for (const legal of [
  {
    label: 'Imprint',
    canonical: '/imprint',
    alias: '/impressum',
    target: 'https://legal.example.test/imprint',
  },
  {
    label: 'Privacy Notice',
    canonical: '/privacy',
    alias: '/datenschutz',
    target: 'https://legal.example.test/privacy',
  },
]) {
  test(`${legal.label}: logged-out link and redirects`, async ({ page, request }) => {
    // Login page shows the configured local alias.
    await page.goto('/login');

    const link = page.getByRole('link', {
      name: legal.label,
      exact: true,
    });

    await expect(link).toHaveAttribute('href', legal.alias);

    // The configured alias redirects to the external legal page.
    const aliasResponse = await request.get(legal.alias, {
      maxRedirects: 0,
    });

    expect(aliasResponse.status()).toBeGreaterThanOrEqual(300);
    expect(aliasResponse.status()).toBeLessThan(400);
    expect(aliasResponse.headers()['location']).toBe(legal.target);

    // The canonical public route redirects to the same destination.
    const canonicalResponse = await request.get(legal.canonical, {
      maxRedirects: 0,
    });

    expect(canonicalResponse.status()).toBeGreaterThanOrEqual(300);
    expect(canonicalResponse.status()).toBeLessThan(400);
    expect(canonicalResponse.headers()['location']).toBe(legal.target);
  });
}