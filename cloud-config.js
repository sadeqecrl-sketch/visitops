/* Optional: pre-configure cloud storage for EVERY device that opens this site, so team members only
 * have to type the workspace password. Leave provider empty to configure in the app instead.
 *
 * window.VO_CLOUD = {
 *   provider: 'appwrite',               // 'appwrite' | 'dropbox' | 'gdrive' | 'onedrive' | '' (browser only)
 *   workspace: 'myteam',                // optional name, letters/digits
 *   poll: 30,                           // sync every N seconds (0 = manual)
 *   appwrite: { endpoint: 'https://cloud.appwrite.io/v1', project: '', db: '', col: '' },
 *   dropbox:  { clientId: '' },         // Dropbox App key
 *   gdrive:   { clientId: '' },         // Google OAuth Client ID
 *   onedrive: { clientId: '' }          // Microsoft Application (client) ID
 * };
 * Never put the workspace password in this file.
 */
window.VO_CLOUD = window.VO_CLOUD || {};
