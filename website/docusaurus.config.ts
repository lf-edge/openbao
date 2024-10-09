import { themes as prismThemes } from "prism-react-renderer";
import type { Config } from "@docusaurus/types";
import type * as Preset from "@docusaurus/preset-classic";
import { includeMarkdown } from "@hashicorp/remark-plugins";
import path from "path";

const config: Config = {
  title: "OpenBao",
  tagline: "Manage, store, and distribute sensitive data",
  favicon: "img/favicon.svg",

  // Set the production url of your site here
  url: "https://openbao.org",
  // Set the /<baseUrl>/ pathname under which your site is served
  // For GitHub pages deployment, it is often '/<projectName>/'
  baseUrl: "/",
  trailingSlash: true,

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: "openbao", // Usually your GitHub org/user name.
  projectName: "openbao", // Usually your repo name.

  onBrokenLinks: "throw",
  onBrokenMarkdownLinks: "warn",
  // ignore broken anchors as most of them are false positives
  onBrokenAnchors: "ignore",

  // Even if you don't use internationalization, you can use this field to set
  // useful metadata like html lang. For example, if your site is Chinese, you
  // may want to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: "en",
    locales: ["en"],
  },
  staticDirectories: ["public"],

  presets: [
    [
      "classic",
      {
        docs: {
          sidebarPath: "./sidebars.ts",
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl: "https://github.com/openbao/openbao/tree/main/website/",
          beforeDefaultRemarkPlugins: [
            [
              includeMarkdown,
              {
                resolveMdx: true,
                resolveFrom: path.join(process.cwd(), "content", "partials"),
              },
            ],
          ],
          path: "content/docs",
        },
        sitemap: {
          lastmod: 'datetime',
          changefreq: 'hourly',
          priority: 0.5,
          filename: 'sitemap.xml',
        },
        blog: {
          blogTitle: 'OpenBao Blog',
          blogDescription: 'Official blog of the Bao Evangelism Taskforce (BET)',
          path: "content/blog",
        },
        theme: {
          customCss: "./src/css/custom.css",
        },
		gtag: {
		  trackingID: "GTM-MWH2V47T",
		},
      } satisfies Preset.Options,
    ],
  ],
  plugins: [
    [
      "@docusaurus/plugin-content-docs",
      {
        id: "api-docs",
        path: "content/api-docs",
        routeBasePath: "api-docs",
        sidebarPath: "./sidebarsApi.ts",
        editUrl: "https://github.com/openbao/openbao/tree/main/website/",
        beforeDefaultRemarkPlugins: [
          [
            includeMarkdown,
            {
              resolveMdx: true,
              resolveFrom: path.join(process.cwd(), "content", "partials"),
            },
          ],
        ],
      },
    ],
    require.resolve("docusaurus-lunr-search"),
  ],

  themeConfig: {
    navbar: {
      title: "OpenBao",
      logo: {
        alt: "OpenBao Logo",
        src: "img/logo-black.svg",
        srcDark: "img/logo-white.svg",
      },
      items: [
        {
          to: "/blog/",
          label: "Blog",
          position: "left",
        },
        {
          to: "/docs/",
          label: "Docs",
          position: "left",
        },
        { to: "/api-docs/", label: "API", position: "left" },
        {
          to: "/downloads",
          label: "Downloads",
          position: "left",
        },
        {
          type: "dropdown",
          label: "Community",
          position: "left",
          items: [
            {
              label: "GitHub Discussions",
              href: "https://github.com/openbao/openbao/discussions",
            },
            {
              label: "Matrix Chat Server",
              href: "https://chat.lfx.linuxfoundation.org/",
            },
            {
              label: "LF Edge Wiki",
              href: "https://lf-edge.atlassian.net/wiki/spaces/OP/overview",
            },
            {
              label: "Charter",
              to: "pathname:///assets/OpenBao-Technical-Charter-Final-2024-05-08.pdf",
              target: "_blank",
            },
          ],
        },
        {
          href: "https://github.com/openbao/openbao",
          label: "GitHub",
          position: "right",
        },
      ],
    },
    footer: {
      copyright: [
        `Copyright © ${new Date().getFullYear()} OpenBao a Series of LF Projects, LLC <br>`,
        `For web site terms of use, trademark policy and other project policies please see <a href="https://lfprojects.org">lfprojects.org</a>. <br>`,
        ` OpenBao is a <a href="https://wiki.lfedge.org/display/LE/Stage+1%3A+At+Large">Stage One project</a> at`,
        `<a href="https://www.lfedge.org/"><img src="/img/lfedge-logo.svg" alt="LF Edge Logo" width="90px"></a>.`,
        `<br><br><a href="/sitemap.xml">Sitemap</a>`,
      ].join(" "),
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ["hcl"],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
