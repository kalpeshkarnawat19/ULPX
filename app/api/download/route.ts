import { NextResponse } from 'next/server';

export async function GET() {
  // GitHub provides a stable redirect URL for the latest release's source zip.
  // For release *assets* (uploaded .zip files), we fetch the latest release
  // using the per-release endpoint which is less likely to hit rate limits,
  // and fall back to the direct tarball URL if needed.

  const REPO = 'kalpeshkarnawat19/ULPX';

  try {
    const headers: Record<string, string> = {
      'Accept': 'application/vnd.github+json',
      'User-Agent': 'ULPX-Website',
    };

    if (process.env.GITHUB_TOKEN) {
      headers['Authorization'] = `Bearer ${process.env.GITHUB_TOKEN}`;
    }

    // Use /releases/latest instead of /releases (single object, lighter call)
    const res = await fetch(
      `https://api.github.com/repos/${REPO}/releases/latest`,
      {
        headers,
        next: { revalidate: 3600 },
      }
    );

    if (res.ok) {
      const release = await res.json();
      const zipAsset = release?.assets?.find((asset: any) =>
        asset.name.endsWith('.zip')
      );

      if (zipAsset?.browser_download_url) {
        return NextResponse.redirect(zipAsset.browser_download_url);
      }
    }

    // Fallback: redirect to GitHub's built-in latest release page
    // which always works without API auth
    return NextResponse.redirect(
      `https://github.com/${REPO}/releases/latest`
    );
  } catch {
    // Ultimate fallback — send user to the releases page directly
    return NextResponse.redirect(
      `https://github.com/${REPO}/releases/latest`
    );
  }
}
