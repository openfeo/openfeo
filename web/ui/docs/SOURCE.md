# Where these files come from

`web/ui` is a copy of the OpenFeO design system in code. The design system itself is a
document the maintainer keeps outside this repository; it stays the source. A token, a class
or a guideline changes there first and is copied across, and where building the panel shows
the design system wrong, the fix goes back to it (`gaps.md` lists what is waiting).

Copied on 11 November 2026, file for file:

| Here | In the design system | SHA-256 as copied |
|---|---|---|
| `tokens.json` | `tokens.json` | `9bb9c39dc0263b307b0dc97204ab6ccb874ef7cbbe9b3ce3c2b375436a3aa6c1` |
| `ofo.css` | `components/bundle.css` | `7a99fe8bbead25e5ede25ebc9f91c3bbc5ffd3d7fdbc998d31394e62bc9e5cc1` |
| `fonts/InstrumentSans-OFL.txt` | `fonts/InstrumentSans-OFL.txt` | `c27a3c53c3beed7f5c26853afa15991478ff7145d3754a36b0382f84e10c0d03` |
| `fonts/InstrumentSans-Variable.woff2` | `fonts/InstrumentSans-Variable.woff2` | `2ee17598a98d8a59e4df8152d015bec9ab8e4d5672cc0ab42bef806b568e3971` |
| `fonts/JetBrainsMono-OFL.txt` | `fonts/JetBrainsMono-OFL.txt` | `403581b69dac5cff4079205e01c6b467e56af449ecbd7247693ddb1baafa005b` |
| `fonts/JetBrainsMono-Variable.woff2` | `fonts/JetBrainsMono-Variable.woff2` | `18be452724bfdc236c074ca94a249a7f41a86752c7d04ab258ce9ed5651f6a7e` |
| `logos/openfeo-favicon.svg` | `Logos / openfeo-favicon.svg` | `f82ae25981305641d056f2a5a78d242466acdae8922a286b09b48045fb098725` |
| `logos/openfeo-mark-light.svg` | `Logos / openfeo-mark-light.svg` | `a01214a996ace0aaca9d6dff62a4201841b14f74321a504bcaf928da279227a8` |
| `logos/openfeo-mark.svg` | `Logos / openfeo-mark.svg` | `eb344c97d470c9d3878ec77f01406e505d63f70ecba9f326b7d0b402481e1636` |
| `logos/openfeo-wordmark-on-dark.svg` | `Logos / openfeo-wordmark-on-dark.svg` | `8d28175e4a9ab2b7935f10c112a9bb31c26025318e37700247fbafa300758b38` |
| `logos/openfeo-wordmark-on-light.svg` | `Logos / openfeo-wordmark-on-light.svg` | `704d25f38d74587a56a57485bd80754dd5684f28350c33eceaa6eda2ad2c6f9f` |
| `logos/README.md` | `assets/Logos/README.md` | `37e8a0989bf7bc8111e9f1fe06d3a7d766daf4baef17184d97dba08506cc0c2a` |
| `docs/brand.md` | `README.md` | `e7dc87c79c4f2653f77901ff20215961df88e7172d1a1f40df3f66896fb898d2` |
| `docs/components/Banner.md` | `components/Banner/README.md` | `f9d9a51e1f8247506515bca72333e3d50720aff67d5c13345efabd44b5a45767` |
| `docs/components/Brand.md` | `components/Brand/README.md` | `254dc5a002e8c5c02658cf7f2f8e56d498787dafce51bd7058a954b65b359c6b` |
| `docs/components/Button.md` | `components/Button/README.md` | `405aafd7ce9d5c502eaaae339d47ce214a7bd19b723ee24735a1fb7664321347` |
| `docs/components/Choice.md` | `components/Choice/README.md` | `48942a9c6831b75f34fbd29131718354a5c12d308f1f845de1b138bf7097d657` |
| `docs/components/CodeBlock.md` | `components/CodeBlock/README.md` | `0438c62c9211fb9dcd60f0fe98c6b28dfe8a9338b97a39a3ade619f75455f86d` |
| `docs/components/DataTable.md` | `components/DataTable/README.md` | `73ee29e7302eb0c660caf59a8fb24814b9e70161b775e7eca812873ccccbb948` |
| `docs/components/Dialog.md` | `components/Dialog/README.md` | `8e2e0b5daa45243b4c411fcfac883a33762fc0ea788228872b8a1fa40f86864f` |
| `docs/components/DocsLayout.md` | `components/DocsLayout/README.md` | `f877c2fd5e79bfdd9b80a0398cf2a36b70f0951028c6e3f993564f446841f88a` |
| `docs/components/DownloadCard.md` | `components/DownloadCard/README.md` | `87434fec83e8605f1c0de1cfe922fe961785801541b96e431823da280d7033bc` |
| `docs/components/EmptyState.md` | `components/EmptyState/README.md` | `08057b0e15eb2ea5e384ab114282764a10f4966358c50e5b8262c37c7c8f0d90` |
| `docs/components/FeatureGrid.md` | `components/FeatureGrid/README.md` | `fd1eda92b3ccaf454e77ab25170d679663555dac3c38c17c8d365b4dd2a8f0d7` |
| `docs/components/Field.md` | `components/Field/README.md` | `a5f0e760a5abfd56d6202191f070fd6270d3e3668bbc162df2dc2f3c2549c6ed` |
| `docs/components/FormSection.md` | `components/FormSection/README.md` | `a0751e17dc8c28e702a4e2ffbf3be7ba6a3418f993322ffee7bdb9f8da04ae93` |
| `docs/components/Hero.md` | `components/Hero/README.md` | `bc172b184a07afb29bfc20a991f6256cf587036a18b63e50b9b9bc5df309ab2a` |
| `docs/components/InterfaceCard.md` | `components/InterfaceCard/README.md` | `1b5d4fede8fa62ef4f102049e692a30c4d0d20318d85a63c4cef26a3da232e3d` |
| `docs/components/MarkMotion.md` | `components/MarkMotion/README.md` | `b9e374de63c3c4489816f7d618b5fcdb25cb2a8b8febeb9b2487e0be23e41d23` |
| `docs/components/Menu.md` | `components/Menu/README.md` | `1780b28930b08f39dfcef5eb6eb2e0c76be087f0796c8b39857460dfc4310ae0` |
| `docs/components/Nav.md` | `components/Nav/README.md` | `7c53956d36d0270f7a2b5e6c70baae27d0d5e8d2547e80598628323328bdc8dd` |
| `docs/components/PageHeader.md` | `components/PageHeader/README.md` | `a5272a6c4eeb3c027fcc19b7764696e478201098da6c69aadd4809ccf23c2f20` |
| `docs/components/PageShell.md` | `components/PageShell/README.md` | `677e71d735733390137d75af6502de74907607f5d03a744325454e23724512c2` |
| `docs/components/PortStrip.md` | `components/PortStrip/README.md` | `984a4ba7ef02c8b923cbf818c5a0184580464a263eb32e38a29096ca214a5f82` |
| `docs/components/Segmented.md` | `components/Segmented/README.md` | `bc57cb9f3c1a33dfcc81853d908ac6b1cb48f34c7610dabf259de5c7e3fe4bf8` |
| `docs/components/SiteFooter.md` | `components/SiteFooter/README.md` | `c4696997209956c9fba2942bcaf3d3ea31afb0713838cd62e55a2e2b85dfcb4f` |
| `docs/components/SiteHeader.md` | `components/SiteHeader/README.md` | `b9fe592f0a2f69938d2df88af1f333643680d94f2a244a86e123242b7003b213` |
| `docs/components/Skeleton.md` | `components/Skeleton/README.md` | `5c6fd5095b8d7e0e67ca36af44a50da9ddb11ba45f500568612307e1e64b3efd` |
| `docs/components/StatTile.md` | `components/StatTile/README.md` | `fc9abfbbd9fa6358c7254d11fc8090539675fb98b4135fd97f3d35e4de360c20` |
| `docs/components/StatusPill.md` | `components/StatusPill/README.md` | `2d524563f743b668eb8fbecb71372b5d830f4dd0d4143689728f2e077a63c922` |
| `docs/components/Tabs.md` | `components/Tabs/README.md` | `3ecaade310f60aaa326ca5f86ac1154e050ddae44180a7bdbaf3418243d1511e` |
| `docs/components/ThroughputChart.md` | `components/ThroughputChart/README.md` | `1ab42b64ce5bfdf155e9652e5d7d751b2feeeeded1c4a6305266b230a305494d` |
| `docs/components/Toast.md` | `components/Toast/README.md` | `5270d540bb6e03966c6c0baa5bc7fd329f83dc61284d61070239e0aa0f85dcd4` |
| `docs/components/Toggle.md` | `components/Toggle/README.md` | `2f983e00bf89f1d7025acc487a93a3d6ca14ccbde65c98de85879f6d70d475a0` |

The one change to a copied file: `ofo.css` begins with the two licence lines every source
file in this repository carries; from its third line on it is the design system's
`components/bundle.css`, and the checksum above is of that file without them.

Not copied: `components/bundle.js` (the mark's animation, which the panel's first part does
not use), each component's `preview.html`, and the document's own scaffolding.

Written here, not copied: `tokens.css` (by `scripts/tokens.mjs` from `tokens.json`),
`additions.css`, and everything under `src/`.

The brand guide's last section speaks of an `@openfeo/ui` package in a repository of its
own. This directory is that package; it lives in the router's repository.
