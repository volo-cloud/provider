Deployment of the Volocloud terraform provider documentation to GitHub pages.
Need to have mike and it's addons installed locally on your computer

To do a new deployment follow these steps:

- Copy the docs folder from the provider
- Run mike deploy: `mike deploy x.y.z -u`
- Run mike alias: `mike alias x.y.z latest -u`
- Run mike default: `mike set-default latest`
