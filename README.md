# Issue M-1: Missing staleness check in PythOracle can lead to forced liquidations and theft of funds from borrowers. 

Source: https://github.com/sherlock-audit/2024-12-mach-finance-judging/issues/41 

## Found by 
0xRiO, 0xc0ffEE, 0xpetern, bbl4de, c3phas, d4y1ight, eeyore, fuzzysquirrel, miaowu, silver\_eth, vahdrak1, zanderbyte, zxriptor
### Summary

The Pyth integration contract uses the `getPriceUnsafe()` function to retrieve the latest reported price from a specified price feed. 

However, Pyth does not have sponsored price feeds on the Sonic chain, that will guaranty the proper data freshness. As such, this function depends on users or the Mach protocol to update the price data with fresh values. 

As a result, the prices retrieved using `getPriceUnsafe()` can be significantly outdated, even with the protocol best efforts to maintain price freshness due to its keeper/bot outages.

The documentation for `getPriceUnsafe()` incorrectly suggests that it will revert with a `StalePrice` error when the price is outdated. In reality, this function returns a price with its associated timestamp, regardless of how old the timestamp is, as long as the price was updated at some point in the past.

This issue becomes critical if the prices used by the protocol are not updated for extended periods, during which significant price changes could occur for assets being borrowed or used as collateral in the project.

### Root Cause

The Pyth integration contract does not perform a staleness check, and did not switch to fallback oracle in such situation. It only verifies that the price is > 0 [(here)](https://github.com/sherlock-audit/2024-12-mach-finance/blob/main/contracts/src/Oracles/Pyth/PythOracle.sol#L93-L104), which is insufficient. 

Although Compound V2 does not enforce staleness checks in its Chainlink oracle integration, the situation differs because Chainlink prices cannot be updated directly by anyone. Even stale prices from Chainlink are deemed acceptable under these circumstances, especially to avoid blocking liquidations.

In contrast, Pyth allows anyone to update the price feed (via `updatePriceFeeds()` function), in situation where the new price adheres to the rule that it must be newer than the previous price and is a valid Pyth price component for given price feed.

This introduces a vulnerability where price updates can be manipulated to extract value from users.

### Internal pre-conditions

None.

### External pre-conditions

- Pyth prices have not been updated for an extended period.

### Attack Path

An attacker can construct a transaction that updates the price feed with a desired value reported at a timestamp between the last update and the current time. This enables the attacker to inflate the price of borrowed assets and deflate the price of collateral assets, leading to forced liquidations.

The reported prices can originate from any valid price component with timestamp within the allowed timeframe. As observed in real-world scenarios, asset prices can rise by 10% in one day and fall by 20% on another day (e.g., FTM).

Consider a three-day timeframe during which Pyth prices for two supported assets are not updated:

1. **Day 1**: Asset A and Asset B prices are accurately reported.
2. **Day 2**: Both assets experience a 10% price increase, but the prices are not updated in Pyth. Although exploitation is possible at this stage, the attacker may wait another day.
3. **Day 3**: Both assets experience a 20% price drop.

The attacker can then update:
- The borrow asset price to the inflated value from Day 2 (+10%).
- The collateral asset price to the deflated value from Day 3 (-20%, or ~-10% from Day 1).

This manipulation allows the attacker to extract maximum liquidable value from users, profiting from the actual prices of the assets.

This attack would not be possible with fresh price updates, as the user shortfall would not fall below 1 in the given scenario of volatile prices.

### Impact

- Direct loss of funds from forced liquidation of users, in situations where accurate price updates would prevent shortfalls from falling below 1.

### Mitigation

- Enforce a staleness check when using `getPriceUnsafe()`. Utilize a fallback API3 oracle if freshness criteria are not met.
- Develop and deploy an off-chain bot (with a backup mechanism) to push fresh Pyth data to the Sonic network. The bot should use a short heartbeat and low price deviation triggers.

# Issue M-2: Market may not increase total reserves during times of high volume/frequent transactions 

Source: https://github.com/sherlock-audit/2024-12-mach-finance-judging/issues/44 

## Found by 
zxriptor
## Summary

The issue arises from the fact that rate variables are set on a per-second basis, and the `accrualBlockTimestamp` variable is updated (i.e., the interest accrual window moves forward) even if no interest is added due to precision loss.


## Vulnerability Detail

In the `BaseJumpRateModelV2.sol`, `multiplierPerTimestamp` is divided by `timestampsPerYear` to calculate the multiplier per second. Considering that `baseRatePerYear` is likely to have the same or similar values as in the Compound v2 protocol, this timestamp-based calculation results in values approximately 15 times lower compared to the original "block-per-year" formula.

```solidity
    function updateJumpRateModelInternal(
        uint256 baseRatePerYear,
        uint256 multiplierPerYear,
        uint256 jumpMultiplierPerYear,
        uint256 kink_
    ) internal {
        baseRatePerTimestamp = ((baseRatePerYear * BASE) / timestampsPerYear) / BASE;
>>      multiplierPerTimestamp = (multiplierPerYear * BASE) / (timestampsPerYear * kink_);
        jumpMultiplierPerTimestamp = ((jumpMultiplierPerYear * BASE) / timestampsPerYear) / BASE;
        kink = kink_;

        emit NewInterestParams(baseRatePerTimestamp, multiplierPerTimestamp, jumpMultiplierPerTimestamp, kink);
    }
```

These lower values, combined with the fact that the Sonic network produces at least 1 block per second, make the Machi protocol more prone to precision loss. This issue is particularly significant during high-frequency interactions with the protocol, as these trigger `CToken.accrueInterest` calculations each time.

Particularly in `CToken.accrueInterest()`, the value to add to reserves is calculated as the interest accumulated multiplied by the reserve factor. The reserve factor is expected to have a value less than 1e18, as it represents the percentage of interest that must be allocated to reserves.

```solidity
        uint256 totalReservesNew =
            mul_ScalarTruncateAddUInt(Exp({mantissa: reserveFactorMantissa}), interestAccumulated, reservesPrior);
```

This can lead to truncation and result in zero if the interest accumulated between subsequent calls to `accrueInterest` is too low, resulting in just a few wei.

For example, the reserve factor for cWBTC in the Compound v2 protocol is 0.3 ([link](https://etherscan.io/address/0xccF4429DB6322D5C611ee964527D42E5d685DD6a#readProxyContract#F20)). This means that if the interest accumulated is less than 4 wei, the result will be zero due to truncation: `3 wei * 0.3 = 0.9 => 0`.

## PoC

Consider the cWBTC market with the following parameters:

1 SONIC = 1 USD
1 WBTC  = 100,000 USD

totalCash: 100 WBTC (or 10,000,000 USD)
reserveFactor: 0.3
multiplierPerYear: 0.25e18
utilizationRate: 5%

Total borrows: 5 WBTC.

Insert this test into `CToken.t.sol`:

```solidity
function test_accrueInterest_PoC() public {
    vm.prank(admin);
    cWbtcDelegator._setReserveFactor(300000000000000000); // 0.3

    uint256 wBTCInitialBalance = 100 * (10 ** wbtc.decimals());
    deal(address(wbtc), bob, wBTCInitialBalance);

    // Supply wBTC as collateral
    vm.startPrank(bob);
    wbtc.approve(address(cWbtcDelegator), type(uint256).max);
    cWbtcDelegator.mint(wBTCInitialBalance);
    vm.stopPrank();

    uint aliceCollateral = 1 * 1e6 ether;
    deal(alice, aliceCollateral);

    // deposit and enter market
    vm.startPrank(alice);
    cSonic.mintAsCollateral{value: aliceCollateral}();

    // Fetch initial liquidity and shortfall
    (, uint256 liquidity, uint256 shortfall) = comptroller.getAccountLiquidity(alice);
    // console.log("Initial liquidity/shortfall    :", liquidity, shortfall);

    // Fetch wBTC price
    uint wbtcPrice = priceOracle.getUnderlyingPrice(CToken(address(cWbtcDelegator)));
    uint borrowableWBTC = (liquidity * 1e36) / wbtcPrice / 1e18;

    // Borrow max wBTC
    cWbtcDelegator.borrow(borrowableWBTC);

    uint utilizationRate = (cWbtcDelegator.totalBorrows() * 1e18) / (cWbtcDelegator.totalBorrows() + cWbtcDelegator.getCash());
    console.log("Utilization Rate (%)            :", utilizationRate * 100 / 1e18);

    uint totalReserves = cWbtcDelegator.totalReserves();
    console.log("totalReserves (wBTC)            :", totalReserves);

    // Fetch initial borrow balance
    uint initialBorrowBalance = cWbtcDelegator.borrowBalanceCurrent(alice);

    {

    uint secs = 86_400;
    uint period = 10;

    // vm.warp(block.timestamp + secs);
    // cWbtcDelegator.accrueInterest(); 

    for (uint256 i = 0; i < secs / period; ++i) {
        vm.warp(block.timestamp + period);
        cWbtcDelegator.accrueInterest(); // Accrue interest on the wBTC market
    }

    console.log("");
    console.log(secs, "sec passed");
    console.log("");

    }

    // Fetch updated borrow balance
    uint updatedBorrowBalance = cWbtcDelegator.borrowBalanceCurrent(alice);

    // Calculate accrued interest
    uint interestAccrued = updatedBorrowBalance - initialBorrowBalance;
    console.log("Borrower interest accrued (wBTC):", interestAccrued);

    uint updatedTotalReserves = cWbtcDelegator.totalReserves();
    console.log("totalReserves (wBTC)            :", updatedTotalReserves);

    vm.stopPrank();
}

```

Output when test is run with the `accrueInterest` called once per 10 seconds for 1 day:
```bash
$ forge test --match-test test_accrueInterest_PoC -vvv
Ran 1 test for test/CToken.t.sol:CTokenTest
[PASS] test_accrueInterest_PoC() (gas: 141057857)
Logs:
  Utilization Rate (%)           : 5
  totalReserves (wBTC)           : 0

  86400 sec passed

  Borrower interest accrued (wBTC): 21404
  totalReserves (wBTC)           : 0

```
As can be seen, reserves were not increased and stayed at 0.
At the same time, a real `totalReserves` increase must be `21404 * 0.3 = 6421`.

## Impact

Market (CToken) may not accrue total reserves.

Preconditions:
- High volume of transactions (once every 10 to 15 seconds).
- Market utilization rate is no more than 5 - 10 %.  

## Code Snippet

https://github.com/sherlock-audit/2024-12-mach-finance/blob/main/contracts/src/BaseJumpRateModelV2.sol#L155

https://github.com/sherlock-audit/2024-12-mach-finance/blob/main/contracts/src/CToken.sol#L359-L360


## Recommendation

Do not update `accrualBlockTimestamp` if calculations result in zero.


