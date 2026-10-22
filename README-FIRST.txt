VisitOps - EASY MODE (Letter Desk style)

1. Go to https://app.netlify.com/drop and drag THIS FOLDER (or its files) in.
   (Any static web host works. Use https.)
2. Open the address Netlify gives you.
3. First screen: "First time: create the administrator". Choose your email and password.
4. To share the data with your team, click "Connect cloud storage"
   (Appwrite, Dropbox, Google Drive or OneDrive) and choose a workspace password.
   Every device uses the same settings and the same workspace password.

Optional: edit cloud-config.js BEFORE uploading to pre-fill the provider settings for everyone
(never put the workspace password in it).

Full guide: docs/EASY-MODE.md in visitops-production.zip.
Note: in easy mode permissions are applied by the app in each browser. For server-enforced
permissions use the Netlify "server mode" described in the full project.
