# instawow-tsm

[Instawow](https://github.com/layday) plugin for
[TradeSkillMaster](https://www.tradeskillmaster.com/). Supports addon
downloading and fetching auction pricing data, all in CLI.

1. Install the plugin:

    ```
    pip install -U -e 'git+https://github.com/seirl/instawow-tsm#egg=instawow-tsm'
    ```

2. Configure the plugin with your TSM credentials:

    ```
    instawow tsm configure
    ```

3. Install the `TradeSkillMaster` and `TradeSkillMaster_AppHelper` addons:

    ```
    instawow install tsm:tradeskillmaster
    instawow install tsm:tradeskillmaster_apphelper
    ```

4. Refresh the auction pricing data:

    ```
    instawow tsm update
    ```
