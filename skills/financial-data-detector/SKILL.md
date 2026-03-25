# Financial Data Detector

Detects sensitive financial figures in proximity to financial context keywords. Uses a windowed detection approach: currency amounts are only flagged when within 200 characters of financial context.

## Detection Coverage

### Salary & Compensation
- Salary, compensation, CTC, base pay, annual pay, monthly salary
- Take-home, net pay, gross pay, earnings, income, stipend

### Bonus & Incentives
- Performance bonuses, annual/quarterly bonuses
- Commissions, variable pay, STI, LTI

### Revenue & P&L
- Revenue, net revenue, ARR, MRR, run rate
- Profit, loss, EBITDA, EBIT, operating income
- P&L, income statement, bottom line

### Payroll
- Payroll figures, paycheck/paycheque amounts
- Total payroll, payroll processing amounts

### Budget & Financial Projections
- Budget, forecast, capex, opex
- FY targets, financial plans, 3/5-year plans

### Equity & Stock Options
- RSUs, stock options, vesting amounts
- Cap table figures, valuation, series round amounts
- Pre/post-money valuation

### Funding & Investment
- Venture capital, private equity raises
- Series A/B/C round amounts, IPO, M&A values

### Internal Financial Codes
- Cost center, GL code, WBS element references with amounts
- Budget codes, profit center figures

## Amount Formats Detected
- `$1,234,567`, `£500K`, `€2.3M`, `$1.5B`
- `1,000,000 USD`, `500 thousand dollars`
- `2M`, `500K`, `1.2B`

## Risk Escalation
3 or more distinct financial figures in the same prompt triggers HIGH risk escalation regardless of individual figure severity.

## Output Format
```json
{
  "detected": true,
  "findings": [
    {
      "type": "salary_compensation",
      "name": "Salary / Compensation Figure",
      "severity": "HIGH",
      "amount_hint": "~120K",
      "snippet": "base salary is $120,000 per year...",
      "position": 15
    }
  ],
  "count": 1,
  "distinct_financial_figures": 1,
  "risk_level": "HIGH"
}
```

## Usage
```python
from tools.financial_data_detector import FinancialDataDetector

detector = FinancialDataDetector()
result = detector.analyze("Q3 revenue was $2.3M and EBITDA was $450K")
print(result["risk_level"])  # CRITICAL (multiple figures)
```
