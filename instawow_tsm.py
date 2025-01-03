import aiohttp
import asyncio
import click
import codecs
import datetime
import functools
import gzip
import json
import sys
import textwrap
import urllib.parse
import time
from io import BytesIO
from datetime import timezone
from getpass import getpass
from hashlib import sha256
from pathlib import Path
from loguru import logger

import instawow.plugins
from instawow.definitions import Defn, ChangelogFormat, SourceMetadata
from instawow.results import PkgNonexistent
from instawow.resolvers import BaseResolver, PkgCandidate
from instawow.cli import ConfigBoundCtxProxy


PASSWORD_SALT = codecs.encode("s2s618p502n975825r5qn6s8650on8so", 'rot_13')
TOKEN_SALT = codecs.encode("3SO1PP5RQP5O43S21PO8NPP23O42O703", 'rot13')
APP_VERSION = '41401'

SUCCESS_SYMBOL = click.style('✓', fg='green')
FAILURE_SYMBOL = click.style('✗', fg='red')
WARNING_SYMBOL = click.style('!', fg='blue')

OPENID_URL = 'https://id.tradeskillmaster.com/realms/app/protocol/openid-connect/token'  # noqa


class APIError(Exception):
    pass


class TsmSession:
    def __init__(self):
        self.session = ''
        self.endpoint_subdomains = {
            'login': 'app-server',
            'log': 'app-server',
            'auth': 'app-server',
            'realms2': 'app-server',
        }
        self.aiohttp_session = aiohttp.ClientSession(raise_for_status=True)

    async def __aenter__(self):
        await self.aiohttp_session.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_value, tb):
        await self.aiohttp_session.__aexit__(exc_type, exc_value, tb)

    def _get_url(self, endpoint):
        params = {
            'session': self.session,
            'version': APP_VERSION,
            'time': str(int(time.time())),
            'channel': 'release',
            'tsm_version': '',
        }
        params['token'] = sha256('{}:{}:{}'.format(
            params['version'], params['time'], TOKEN_SALT
        ).encode()).hexdigest()
        url = 'http://{}.tradeskillmaster.com/v2/{}'.format(
            self.endpoint_subdomains[endpoint[0]],
            '/'.join(endpoint)
        )
        return url, params

    async def _req(self, endpoint, data=None):
        url, params = self._get_url(endpoint)
        headers = {}
        method = 'get'
        if data:
            method = 'post'
            data = json.dumps(data)
            data = gzip.compress(data.encode())
            headers['Content-Encoding'] = 'gzip'

        r = await self.aiohttp_session.request(
            method,
            url,
            params=params,
            headers=headers,
            data=data,
        )
        res_data = await r.json()
        if not res_data['success']:
            raise APIError(res_data['error'])
        return res_data

    async def token(self, email, password):
        payload = {
         "username": email,
         "password": password,
         "client_id": "legacy-desktop-app",
         "grant_type": ["password"],
         "code": "",
         "redirect_uri": "",
         "scope": "openid"
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        resp = await self.aiohttp_session.post(
            OPENID_URL,
            data=payload,
            headers=headers,
            ssl=False,
            raise_for_status=True,
        )
        return (await resp.json())

    async def login(self, email, password):
        t = await self.token(email, password)
        login_data = await self._req(
            ['auth'], data={'token': t['access_token']}
        )
        self.endpoint_subdomains.update(login_data["endpointSubdomains"])
        self.session = login_data['session']

    async def status(self):
        return await self._req(['status'])

    async def auctiondb(self, download_url):
        resp = await self.aiohttp_session.get(download_url)
        raw_data = await resp.read()
        if raw_data[:2] == b'\x1f\x8b':
            data = gzip.GzipFile(fileobj=BytesIO(raw_data)).read().decode()
        else:
            data = raw_data.decode()
        return data

    async def addons(self):
        status = await self.status()
        addons = {v['name']: v for v in status['addons']}
        for name, addon in addons.items():
            base_url, params = self._get_url(['addon', addon['name']])
            query_params = urllib.parse.urlencode(params)
            url_with_params = f'{base_url}?{query_params}'
            addon['url'] = url_with_params
        return addons


REALM_PRICING_SOURCES = [
    'AUCTIONDB_NON_COMMODITY_DATA',
    'AUCTIONDB_NON_COMMODITY_SCAN_STAT',
    'AUCTIONDB_NON_COMMODITY_HISTORICAL',
]

REGION_PRICING_SOURCES = [
    'AUCTIONDB_COMMODITY_DATA',
    'AUCTIONDB_COMMODITY_SCAN_STAT',
    'AUCTIONDB_COMMODITY_HISTORICAL',
    'AUCTIONDB_REGION_STAT',
    'AUCTIONDB_REGION_HISTORICAL',
    'AUCTIONDB_REGION_SALE',
]


async def update_tsm_appdata(profile_config, session):
    path = (
        Path(profile_config.addon_dir)
        / 'TradeSkillMaster_AppHelper'
        / 'AppData.lua'
    )
    if not path.exists():
        raise RuntimeError("TSM AppHelper not found")

    current_data = {}
    # Each line is of the format
    # `{data} --<{data_type},{realm},{time}>`
    for lineno, line in enumerate(path.read_text().splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        parts = line.split('--')
        if len(parts) != 2:
            raise RuntimeError(
                "Cannot parse metadata at {}:{}: '{}'"
                .format(
                    path,
                    lineno,
                    line if len(line) < 80 else line[:80] + "...",
                )
            )
        data = parts[0].rstrip(' ')
        comment_data = parts[1].lstrip('<').rstrip('>')
        comment_parts = comment_data.split(',')
        data_type, realm, ts = (
            comment_parts[0], comment_parts[1], int(comment_parts[2])
        )
        current_data[(data_type, realm)] = (data, ts)

    status = await session.status()
    ts = int(time.time())

    # Add realm-specific market data
    for realm in status['realms']:
        for pricing_source in REALM_PRICING_SOURCES:
            url = realm['appDataStrings'][pricing_source]['url']
            data = await session.auctiondb(url)
            current_data[(pricing_source, realm['name'])] = (
                data,
                realm['appDataStrings'][pricing_source]['lastModified'],
            )

    # Add regional market data
    for region in status['regions']:
        for pricing_source in REGION_PRICING_SOURCES:
            url = region['appDataStrings'][pricing_source]['url']
            data = await session.auctiondb(url)
            current_data[(pricing_source, region['name'])] = (
                data,
                region['appDataStrings'][pricing_source]['lastModified'],
            )

    # Add APP_INFO key
    addon_message = "{{id={},msg=\"{}\"}}".format(
        status['addonMessage']['id'], status['addonMessage']['msg']
    )
    new_data = "{{version={},lastSync={},message={},news={}}}".format(
        APP_VERSION,
        ts,
        addon_message,
        status['addonNews']
    )
    current_data[("APP_INFO", "Global")] = (new_data, ts)

    # Write current_data to file
    current_data_raw = ''.join([
        "select(2, ...).LoadData(\"{}\",\"{}\",[[return {}]]) --<{},{},{}>\r\n"
        .format(
            data_type, data_name, data, data_type, data_name, ts
        )
        for (data_type, data_name), (data, ts) in current_data.items()
    ])
    path.write_text(current_data_raw)
    return status


def get_tsm_config_dir(profile_config):
    profile_dir = profile_config.global_config.plugins_config_dir / __name__
    profile_dir.mkdir(exist_ok=True, parents=True)
    tsm_config_path = profile_dir / 'credentials.json'
    return tsm_config_path


async def update_config_creds(profile_config):
    tsm_config_path = get_tsm_config_dir(profile_config)
    async with TsmSession() as session:
        email = input('TSM email: ')
        password = getpass('TSM password: ')
        try:
            await session.login(email, password)
        except APIError as e:
            print(FAILURE_SYMBOL, str(e))
            sys.exit(1)

    tsm_config_path.write_text(json.dumps(
        {'tsm_email': email, 'tsm_password': password}
    ))


def get_tsm_config(profile_config):
    tsm_config_path = get_tsm_config_dir(profile_config)
    if not tsm_config_path.exists():
        raise RuntimeError("TSM is not properly configured. "
                           "Run `tsm configure` first.")
    tsm_config = json.loads(tsm_config_path.read_text())
    if 'tsm_email' not in tsm_config or 'tsm_password' not in tsm_config:
        raise RuntimeError("TSM is not properly configured. "
                           "Run `tsm configure` first.")
    return tsm_config


def cli_status_string(status):
    results = []
    for realm in status['realms']:
        realm_info = []
        for pricing_source in REALM_PRICING_SOURCES:
            realm_info.append("  {} [{}]".format(
                datetime.datetime.fromtimestamp(
                    realm['appDataStrings'][pricing_source]['lastModified']
                ),
                pricing_source.lower(),
            ))
        results.append([
            'realm',
            f'{realm["name"]}-{realm["region"]}',
            '\n'.join(realm_info)
        ])
    for region in status['regions']:
        region_info = []
        for pricing_source in REGION_PRICING_SOURCES:
            region_info.append("  {} [{}]".format(
                datetime.datetime.fromtimestamp(
                    region['appDataStrings'][pricing_source]['lastModified']
                ),
                pricing_source.lower(),
            ))
        results.append([
            'region',
            region['name'],
            '\n'.join(region_info)
        ])

    return '\n'.join(
        f'{SUCCESS_SYMBOL} {click.style(t + ":" + n, bold=True)}\n{l}'
        for t, n, l in results
    )


async def update_tsm_appdata_once(profile_config):
    config = get_tsm_config(profile_config)
    async with TsmSession() as session:
        await session.login(config['tsm_email'], config['tsm_password'])
        status = await update_tsm_appdata(profile_config, session)
        print(cli_status_string(status))


async def update_tsm_appdata_loop(profile_config, delay=600):
    config = get_tsm_config(profile_config)
    while True:
        async with TsmSession() as session:
            await session.login(config['tsm_email'], config['tsm_password'])
            logger.info("Refreshing auction data every {} seconds...", delay)
            status = await update_tsm_appdata(profile_config, session)
            logger.info(
                "Refreshed:\n{}",
                textwrap.indent(cli_status_string(status), '  ')
            )
        await asyncio.sleep(delay)


class TSMResolver(BaseResolver):
    metadata = SourceMetadata(
        id='tsm',
        name='TradeSkillMaster',
        strategies=frozenset(),
        changelog_format=ChangelogFormat.Raw,
        addon_toc_key=None,
    )
    requires_access_token = None
    BASE_URL = 'https://www.tradeskillmaster.com/download/{addon}.zip'

    @functools.cached_property
    def tsm_config(self):
        return get_tsm_config(self._config)

    async def get_addons(self):
        async with TsmSession() as session:
            await session.login(
                self.tsm_config['tsm_email'],
                self.tsm_config['tsm_password']
            )
            addons = await session.addons()
            return addons

    async def _resolve_one(self, defn: Defn, metadata: None) -> PkgCandidate:
        addons = await self.get_addons()
        addons = {k.lower(): v for k, v in addons.items()}
        if defn.alias not in addons:
            raise PkgNonexistent
        addon = addons[defn.alias]

        return PkgCandidate(
            id=defn.alias,
            slug=defn.alias,
            name=addon['name'],
            description=addon['name'],
            url='https://www.tradeskillmaster.com/',
            download_url=addon['url'],
            date_published=datetime.datetime.now(timezone.utc),
            version=addon['version_str'],
            changelog_url='data:,',
        )


@click.group()
def tsm():
    pass


@tsm.command()
@click.pass_obj
def configure(config_ctx: ConfigBoundCtxProxy):
    asyncio.run(update_config_creds(config_ctx.config))


@tsm.command()
@click.pass_obj
def update(config_ctx: ConfigBoundCtxProxy):
    asyncio.run(update_tsm_appdata_once(config_ctx.config))


@tsm.command()
@click.option('-d', '--delay', default=600, type=int,
              help="Refresh delay (seconds)")
@click.pass_obj
def run(config_ctx: ConfigBoundCtxProxy, delay):
    asyncio.run(update_tsm_appdata_loop(config_ctx.config, delay=delay))


@instawow.plugins.hookimpl
def instawow_add_commands():
    return (tsm,)


@instawow.plugins.hookimpl
def instawow_add_resolvers():
    return (TSMResolver,)
