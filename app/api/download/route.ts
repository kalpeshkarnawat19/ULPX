import { NextResponse } from 'next/server';

export async function GET() {
  try {
    const headers: Record<string, string> = {
      'Accept': 'application/vnd.github+json',
      'User-Agent': 'ULPX-Website',
    };

    if (process.env.GITHUB_TOKEN) {
      headers['Authorization'] = `Bearer ${process.env.GITHUB_TOKEN}`;
    }

    const res = await fetch(
      'https://api.github.com/repos/kalpeshkarnawat19/ULPX/releases',
      {
        headers,
        next: { revalidate: 3600 }, // Cache response for 1 hour
      }
    );

    if (!res.ok) throw new Error(`GitHub API HTTP ${res.status}`);

    const releases = await res.json();
    const latestRelease = releases[0];
    const zipAsset = latestRelease?.assets?.find((asset: any) =>
      asset.name.endsWith('.zip')
    );

    if (!zipAsset?.browser_download_url) {
      return NextResponse.json({ error: 'Release asset ZIP not found' }, { status: 404 });
    }

    return NextResponse.redirect(zipAsset.browser_download_url);
  } catch (err: any) {
    return NextResponse.json({ error: 'Failed to fetch release', details: err.message }, { status: 500 });
  }
}
