# Refusal Correlation

This is descriptive only because the planned open-source subset has n=3 models.
Do not claim p <= 0.05 from this analysis.

## Model Rates

| Model | LLMKernelBench parser abst. % | LLMKernelBench safety refus. % | XSTest refus. % |
|---|---:|---:|---:|
| deepseek | 0.72 | 0.00 | 13.56 |
| llama | 1.44 | 0.00 | 10.22 |
| qwen3_coder | 4.56 | 0.00 | 15.56 |

Correlation CSV: `results/safety_bench/xstest/correlation.csv`
