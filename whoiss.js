#!/usr/bin/env node
const { pipeline, map, flatTransform } = require('streaming-iterables')
const { parse: urlParse } = require('url')
const nodeDNS = require('dns')
const { promisify } = require('util')
const { lookup } = require('whois-parsed')
const [_, script, ...sites] = process.argv

const resolve4 = promisify(nodeDNS.resolve4)
const resolve6 = promisify(nodeDNS.resolve6)
const resolveMx = promisify(nodeDNS.resolveMx)

function parseSites(site) {
  if (/http:\/\//.test(site)) {
    const url = urlParse(site)
    return { host: url.host, href: url.href }
  }
  return { host: site }
}

async function whois({ host }) {
  try {
    const domain = host.split('.').slice(-2).join('.')
    const data = await lookup(domain)
    return { type: 'whois', data: { host, domain, ...data } }
  } catch (e) {
    return { type: 'whois', data: { host, domain, error: e.stack } }
  }
}

async function dns({ host }) {
  return Promise.all([
    resolve4(host, { ttl: true }).then(data => ({ type: 'dns', data: { host, data } }),
      e => ({ type: 'dns', data: { host, error: e.stack } })),
    resolve6(host, { ttl: true }).then(data => ({ type: 'dns', data: { host, data } }),
      e => ({ type: 'dns', data: { host, error: e.stack } })),
    resolveMx(host, { ttl: true }).then(data => ({ type: 'dns', data: { host, data } }),
      e => ({ type: 'dns', data: { host, error: e.stack } }))
  ])
}

async function main() {
  const data = pipeline(
    () => sites,
    map(parseSites),
    flatTransform(Infinity, (node) => Promise.all([whois(node), dns(node),]))
  )
  for await (const info of data) {
    switch (info.type) {
      case 'whois': console.log(info.data); break
      case 'dns': console.log(info.data); break
    }
  }
}

main().catch(error => {
  console.log(error.stack)
  process.exit(1)
})
