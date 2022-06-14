import aiohttp
import asyncio
import click
import datetime
import time
import json
import sys
from hashlib import sha256, sha512
from pathlib import Path
from getpass import getpass

import instawow.plugins


PASSWORD_SALT = "f2f618c502a975825e5da6f8650ba8fb"
TOKEN_SALT = "6e8fd9d5da4f1cd0e64ad4d082be477c"
APP_VERSION = '403'

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
        return r

    async def login(self, email, password):
        email_hash = sha256(email.lower().encode()).hexdigest()
        initial_pass_hash = sha512(password.encode()).hexdigest()
        pass_hash = sha512(
            '{}{}'.format(initial_pass_hash, PASSWORD_SALT).encode()
        ).hexdigest()
        resp = await self._req(['login', email_hash, pass_hash])
        login_data = await resp.json()
        if not login_data['success']:
            raise APIError(login_data['error'])
        self.endpoint_subdomains.update(login_data["endpointSubdomains"])
        self.session = login_data['session']

    async def status(self):
        resp = await self._req(['status'])
        return (await resp.json())

    async def auctiondb(self, download_url):
        resp = await self.aiohttp_session.get(download_url)
        return (await resp.text())
        # resp = await self._req(['auctiondb', data_type, str(id)])
        # return (await resp.json())['data']


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
        parts = line.split('--')
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
        data = await session.auctiondb(realm['downloadUrl'])
        current_data[('AUCTIONDB_MARKET_DATA', realm['name'])] = (
            data,
            realm['lastModified'],
        )

    # Add regional market data
    for region in status['regions']:
        data = await session.auctiondb(region['downloadUrl'])
        current_data[('AUCTIONDB_MARKET_DATA', region['name'])] = (
            data,
            region['lastModified'],
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


async def update_config_creds(config_path):
    async with TsmSession() as session:
        email = input('TSM email: ')
        password = getpass('TSM password: ')
        try:
            await session.login(email, password)
        except APIError as e:
            print(FAILURE_SYMBOL, str(e))
            sys.exit(1)

    config_path.write_text(json.dumps(
        {'tsm_email': email, 'tsm_password': password}
    ))


async def get_config(manager):
    profile_dir = Path(manager.config.plugin_dir / __name__)
    profile_dir.mkdir(exist_ok=True)
    tsm_config_path = profile_dir / 'tsm.json'
    if not tsm_config_path.exists():
        await update_config_creds(tsm_config_path)
    tsm_config = json.loads(tsm_config_path.read_text())
    if 'tsm_email' not in tsm_config or 'tsm_password' not in tsm_config:
        await update_config_creds(tsm_config_path)
    tsm_config = json.loads(tsm_config_path.read_text())
    return tsm_config


def cli_status_string(status):
    results = []
    for realm in status['realms']:
        results.append([
            'realm',
            f'{realm["name"]}-{realm["region"]}',
            realm['lastModified']
        ])
    for region in status['regions']:
        results.append(['region', region['name'], region['lastModified']])

    return '\n'.join(
        f'{SUCCESS_SYMBOL} {click.style(t + ":" + n, bold=True)}\n'
        f'  database timestamp: {datetime.datetime.fromtimestamp(ts)}'
        for t, n, ts in results
    )


async def update_tsm_appdata_once(manager):
    config = await get_config(manager)
    async with TsmSession() as session:
        await session.login(config['tsm_email'], config['tsm_password'])
        status = await update_tsm_appdata(manager, session)
        print(cli_status_string(status))


@click.command()
@click.pass_obj
def tsmupdate(mw):
    asyncio.run(update_tsm_appdata_once(mw.manager))


@instawow.plugins.hookimpl
def instawow_add_commands():
    return (tsmupdate,)
