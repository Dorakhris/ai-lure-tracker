/**
 * CTI Safe Handling & Defanging Utilities
 * Prevents accidental execution, browser prefetching, or unwanted socket connections.
 */

export function defang(input: string): string {
  if (!input) return '';
  let res = input.trim();

  // Defang protocols
  res = res.replace(/^http:\/\//i, 'hxxp://');
  res = res.replace(/^https:\/\//i, 'hxxps://');
  res = res.replace(/^ftp:\/\//i, 'fxp://');

  // Defang dots in domain/host or IP if not already defanged
  // Avoid double defanging like `[\[.\]]`
  if (!res.includes('[.]')) {
    // If it's a URL, defang the host part or all dots safely
    res = res.replace(/\./g, '[.]');
  }

  return res;
}

export function refang(input: string): string {
  if (!input) return '';
  let res = input.trim();
  res = res.replace(/^hxxps:\/\//i, 'https://');
  res = res.replace(/^hxxp:\/\//i, 'http://');
  res = res.replace(/^fxp:\/\//i, 'ftp://');
  res = res.replace(/\[\.\]/g, '.');
  return res;
}

// Known legitimate multi-tenant or shared hosting services where lures reside on sub-paths
export const ABUSED_LEGITIMATE_DOMAINS = [
  'discordapp.com',
  'discord.com',
  'cdn.discordapp.com',
  'github.com',
  'raw.githubusercontent.com',
  'github.io',
  'huggingface.co',
  'hf.space',
  'notion.site',
  'webflow.io',
  'firebaseapp.com',
  'web.app',
  'drive.google.com',
  'sites.google.com',
  'pages.dev',
  'workers.dev',
  'vercel.app',
  'netlify.app',
  'replit.app',
  'glitch.me',
  'dropbox.com',
  'onedrive.live.com',
  'sharepoint.com'
];

export function isAbusedLegitimateService(value: string): boolean {
  if (!value) return false;
  const refanged = refang(value).toLowerCase();
  try {
    let hostname = '';
    if (refanged.startsWith('http://') || refanged.startsWith('https://')) {
      hostname = new URL(refanged).hostname;
    } else {
      hostname = refanged.split('/')[0];
    }
    return ABUSED_LEGITIMATE_DOMAINS.some(legit => hostname === legit || hostname.endsWith('.' + legit));
  } catch {
    return ABUSED_LEGITIMATE_DOMAINS.some(legit => refanged.includes(legit));
  }
}

export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    } else {
      const textArea = document.createElement('textarea');
      textArea.value = text;
      textArea.style.position = 'fixed';
      textArea.style.left = '-999999px';
      textArea.style.top = '-999999px';
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      const successful = document.execCommand('copy');
      document.body.removeChild(textArea);
      return successful;
    }
  } catch (err) {
    console.error('Failed to copy text: ', err);
    return false;
  }
}
