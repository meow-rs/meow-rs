import { defineConfig } from 'vitepress'

// The landing page (docs/index.html) is served at the Pages site root
// (https://meow-rs.github.io/meow-rs/). This VitePress site is built into
// docs/guide/ and therefore lives one level down, at /meow-rs/guide/.
const base = '/meow-rs/guide/'

export default defineConfig({
  base,
  lang: 'en-US',
  title: 'meow-rs',
  description:
    'Documentation for meow-rs — a high-performance, rule-based tunneling proxy kernel in Rust. Every feature, every config key.',
  cleanUrls: true,
  lastUpdated: true,
  outDir: '../docs/guide',
  // The repo serves the static docs/ folder directly; emit assets under
  // guide/assets so they never collide with the hand-built landing page.
  assetsDir: 'assets',
  head: [
    ['link', { rel: 'icon', type: 'image/png', href: `${base}logo.png` }],
    ['link', {
      rel: 'apple-touch-icon',
      href: 'https://meow-rs.github.io/meow-rs/appicon.png',
    }],
    ['meta', { name: 'theme-color', content: '#ED7E2B' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:title', content: 'meow-rs documentation' }],
    [
      'meta',
      {
        property: 'og:image',
        content: 'https://meow-rs.github.io/meow-rs/appicon.png',
      },
    ],
    [
      'meta',
      {
        property: 'og:description',
        content:
          'Every feature and config key of meow-rs, the Rust proxy kernel — protocols, rules, DNS, transparent proxy, and the REST API.',
      },
    ],
  ],
  themeConfig: {
    logo: '/logo.png',
    siteTitle: 'meow-rs',
    outline: { level: [2, 3], label: 'On this page' },
    nav: [
      // The landing page lives at the Pages site root, one level above this
      // VitePress base — an absolute URL is the only reliable way back to it.
      { text: '← Landing', link: 'https://meow-rs.github.io/meow-rs/' },
      { text: 'Guide', link: '/guide/what-is-meow-rs' },
      { text: 'Configuration', link: '/guide/configuration' },
      { text: 'Rules', link: '/guide/rules' },
      { text: 'REST API', link: '/reference/rest-api' },
      {
        text: 'Links',
        items: [
          { text: 'GitHub', link: 'https://github.com/meow-rs/meow-rs' },
          {
            text: 'Releases',
            link: 'https://github.com/meow-rs/meow-rs/releases/latest',
          },
          {
            text: 'mihomo (upstream)',
            link: 'https://github.com/MetaCubeX/mihomo',
          },
        ],
      },
    ],
    sidebar: [
      {
        text: 'Introduction',
        collapsed: false,
        items: [
          { text: 'What is meow-rs?', link: '/guide/what-is-meow-rs' },
          { text: 'Getting Started', link: '/guide/getting-started' },
          { text: 'Architecture', link: '/guide/architecture' },
        ],
      },
      {
        text: 'Configuration',
        collapsed: false,
        items: [
          { text: 'Overview', link: '/guide/configuration' },
          { text: 'Proxies', link: '/guide/proxies' },
          { text: 'Proxy Groups', link: '/guide/proxy-groups' },
          { text: 'Rules', link: '/guide/rules' },
          { text: 'DNS', link: '/guide/dns' },
          { text: 'Sniffer', link: '/guide/sniffer' },
          { text: 'Listeners', link: '/guide/listeners' },
          { text: 'Transparent Proxy', link: '/guide/transparent-proxy' },
          { text: 'Providers & Subscriptions', link: '/guide/providers' },
          { text: 'Geodata', link: '/guide/geodata' },
          { text: 'Authentication', link: '/guide/authentication' },
        ],
      },
      {
        text: 'Operations',
        collapsed: false,
        items: [
          { text: 'CLI & Service', link: '/guide/cli' },
          { text: 'meow-cli', link: '/guide/meow-cli' },
          { text: 'REST API Reference', link: '/reference/rest-api' },
        ],
      },
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/meow-rs/meow-rs' },
    ],
    editLink: {
      pattern:
        'https://github.com/meow-rs/meow-rs/edit/main/website/:path',
      text: 'Edit this page on GitHub',
    },
    search: { provider: 'local' },
    footer: {
      message:
        'Released under the MIT License. A Rust take on the mihomo proxy kernel.',
      copyright: 'Rules in · packets out · over every wall.',
    },
  },
})
