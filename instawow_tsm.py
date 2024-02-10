import aiohttp
import asyncio
import click
import codecs
import datetime
import gzip
import json
import sys
import textwrap
import time
from io import BytesIO
from datetime import timezone
from getpass import getpass
from hashlib import sha256, sha512
from pathlib import Path
from loguru import logger

import instawow.plugins
from instawow.results import PkgNonexistent
from instawow.pkg_models import Pkg, PkgOptions
from instawow.resolvers import BaseResolver
from instawow.common import Defn, ChangelogFormat, SourceMetadata


PASSWORD_SALT = codecs.encode("s2s618p502n975825r5qn6s8650on8so", 'rot_13')
TOKEN_SALT = codecs.encode("6r8sq9q5qn4s1pq0r64nq4q082or477p", 'rot_13')
APP_VERSION = '413'

SUCCESS_SYMBOL = click.style('✓', fg='green')
FAILURE_SYMBOL = click.style('✗', fg='red')
WARNING_SYMBOL = click.style('!', fg='blue')


class APIError(Exception):
    pass


class TsmSession:
    def __init__(self):
        self.session = ''
        self.endpoint_subdomains = {
            'login': 'app-server',
            'log': 'app-server',
        }
        self.aiohttp_session = aiohttp.ClientSession()

    async def __aenter__(self):
        await self.aiohttp_session.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_value, tb):
        await self.aiohttp_session.__aexit__(exc_type, exc_value, tb)

    async def _req(self, endpoint):
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
        r = await self.aiohttp_session.get(
            'http://{}.tradeskillmaster.com/v2/{}'.format(
                self.endpoint_subdomains[endpoint[0]],
                '/'.join(endpoint)
            ),
            params=params,
        )
        res_data = await r.json()
        if not res_data['success']:
            raise APIError(res_data['error'])
        return res_data

    async def login(self, email, password):
        email_hash = sha256(email.lower().encode()).hexdigest()
        initial_pass_hash = sha512(password.encode()).hexdigest()
        pass_hash = sha512(
            '{}{}'.format(initial_pass_hash, PASSWORD_SALT).encode()
        ).hexdigest()
        login_data = await self._req(['login', email_hash, pass_hash])
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
        # return (await resp.text())
        # resp = await self._req(['auctiondb', data_type, str(id)])
        # return (await resp.json())['data']


REALM_PRICING_SOURCES = {
    'AUCTIONDB_REALM_DATA': 'data',
    'AUCTIONDB_REALM_HISTORICAL': 'historical',
    'AUCTIONDB_REALM_SCAN_STAT': 'scanStat',
}

REGION_PRICING_SOURCES = {
    'AUCTIONDB_REGION_COMMODITY': 'commodity',
    'AUCTIONDB_REGION_HISTORICAL': 'historical',
    'AUCTIONDB_REGION_STAT': 'stat',
    'AUCTIONDB_REGION_SALE': 'sale',
}


async def update_tsm_appdata(manager, session):
    path = (
        Path(manager.config.addon_dir)
        / 'TradeSkillMaster_AppHelper'
        / 'AppData.lua'
    )
    if not path.exists():
        raise RuntimeError("TSM AppHelper not found")

    current_data = {}
    # Each line is of the format
    # `{data} --<{data_type},{realm},{time}>`
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split('--')
        if len(parts) != 2:
            raise RuntimeError("Cannot parse the existing AppData.lua")
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
        for pricing_source, pricingstringkey in REALM_PRICING_SOURCES.items():
            url = realm['pricingStrings'][pricingstringkey]['url']
            data = await session.auctiondb(url)
            current_data[(pricing_source, realm['name'])] = (
                data,
                realm['pricingStrings'][pricingstringkey]['lastModified'],
            )

    # Add regional market data
    for region in status['regions']:
        for pricing_source, pricingstringkey in REGION_PRICING_SOURCES.items():
            url = region['pricingStrings'][pricingstringkey]['url']
            data = await session.auctiondb(url)
            current_data[(pricing_source, region['name'])] = (
                data,
                region['pricingStrings'][pricingstringkey]['lastModified'],
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


def get_config_dir(manager_ctx):
    profile_dir = Path(manager_ctx.config.plugins_dir / __name__)
    profile_dir.mkdir(exist_ok=True)
    tsm_config_path = profile_dir / 'credentials.json'
    return tsm_config_path


async def update_config_creds(manager_ctx):
    tsm_config_path = get_config_dir(manager_ctx)
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


def get_config(manager_ctx):
    tsm_config_path = get_config_dir(manager_ctx)
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
        results.append([
            'realm',
            f'{realm["name"]}-{realm["region"]}',
            '\n'.join(
                f"  "
                f"{datetime.datetime.fromtimestamp(realm['pricingStrings'][pricingstringkey]['lastModified'])} "
                f"[{pricing_source.lower()}] "
                for pricing_source, pricingstringkey
                in REALM_PRICING_SOURCES.items()
            )
        ])
    for region in status['regions']:
        results.append([
            'region',
            region['name'],
            '\n'.join(
                f"  "
                f"{datetime.datetime.fromtimestamp(region['pricingStrings'][pricingstringkey]['lastModified'])} "
                f"[{pricing_source.lower()}] "
                for pricing_source, pricingstringkey
                in REGION_PRICING_SOURCES.items()
            )
        ])

    return '\n'.join(
        f'{SUCCESS_SYMBOL} {click.style(t + ":" + n, bold=True)}\n{l}'
        for t, n, l in results
    )


async def update_tsm_appdata_once(manager):
    config = get_config(manager)
    async with TsmSession() as session:
        await session.login(config['tsm_email'], config['tsm_password'])
        status = await update_tsm_appdata(manager, session)
        print(cli_status_string(status))


async def update_tsm_appdata_loop(manager_ctx, delay=600):
    config = get_config(manager_ctx)
    while True:
        async with TsmSession() as session:
            await session.login(config['tsm_email'], config['tsm_password'])
            logger.info("Refreshing auction data every {} seconds...", delay)
            status = await update_tsm_appdata(manager_ctx, session)
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

    async def get_addons(self):
        config = get_config(self._manager_ctx)
        async with TsmSession() as session:
            await session.login(config['tsm_email'], config['tsm_password'])
            status = await session.status()
            addons = {v['name']: v for v in status['addons']}
            return addons

    async def resolve_one(self, defn: Defn, metadata: None) -> Pkg:
        addons = await self.get_addons()
        addons = {k.lower(): v for k, v in addons.items()}
        if defn.alias not in addons:
            raise PkgNonexistent
        addon = addons[defn.alias]
        return Pkg(
            source=self.metadata.id,
            id=defn.alias,
            slug=defn.alias,
            name=addon['name'],
            description=addon['name'],
            url='https://www.tradeskillmaster.com/',
            download_url=self.BASE_URL.format(addon=addon['name']),
            date_published=datetime.datetime.now(timezone.utc),
            version=addon['version_str'],
            options=PkgOptions.from_strategy_values(defn.strategies),
            changelog_url='data:,',
        )


@click.group()
def tsm():
    pass


@tsm.command()
@click.pass_obj
def configure(mw):
    asyncio.run(update_config_creds(mw.manager.ctx))


@tsm.command()
@click.pass_obj
def update(mw):
    asyncio.run(update_tsm_appdata_once(mw.manager.ctx))


@tsm.command()
@click.option('-d', '--delay', default=600, type=int,
              help="Refresh delay (seconds)")
@click.pass_obj
def run(mw, delay):
    asyncio.run(update_tsm_appdata_loop(mw.manager.ctx, delay=delay))


@instawow.plugins.hookimpl
def instawow_add_commands():
    return (tsm,)


@instawow.plugins.hookimpl
def instawow_add_resolvers():
    return (TSMResolver,)
