const RELEASES_URL = "https://github.com/linx-systems/clamui/releases";
const LATEST_RELEASE_API =
  "https://api.github.com/repos/linx-systems/clamui/releases/latest";

export interface LatestRelease {
  tag: string;
  url: string;
}

const FALLBACK_RELEASE: LatestRelease = {
  tag: "releases",
  url: RELEASES_URL,
};

export async function getLatestRelease(): Promise<LatestRelease> {
  try {
    const headers = new Headers({
      Accept: "application/vnd.github+json",
      "User-Agent": "clamui-website-build",
    });

    const token = process.env.GITHUB_TOKEN;
    if (token) {
      headers.set("Authorization", `Bearer ${token}`);
    }

    const response = await fetch(LATEST_RELEASE_API, {
      headers,
      signal: AbortSignal.timeout(5000),
    });

    if (!response.ok) {
      return FALLBACK_RELEASE;
    }

    const payload = (await response.json()) as {
      tag_name?: unknown;
      html_url?: unknown;
    };

    if (
      typeof payload.tag_name !== "string" ||
      typeof payload.html_url !== "string"
    ) {
      return FALLBACK_RELEASE;
    }

    return {
      tag: payload.tag_name,
      url: payload.html_url,
    };
  } catch {
    return FALLBACK_RELEASE;
  }
}
