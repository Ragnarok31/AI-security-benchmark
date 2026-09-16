

\---



\## 📈 Understanding Results



| Metric | Formula | Meaning |

|--------|---------|---------|

| Precision | TP / (TP + FP) | Of all alerts, how many were real? |

| Recall | TP / (TP + FN) | Of all vulns, how many were caught? |

| F1 Score | 2×P×R / (P+R) | Balanced score |

| TP | True Positives | Correctly found vulnerabilities |

| FP | False Positives | False alarms |

| FN | False Negatives | Missed vulnerabilities |



\*\*High Precision\*\* = trustworthy alerts, few false alarms  

\*\*High Recall\*\* = catches most vulnerabilities, may have noise  

\*\*High F1\*\* = best overall balance



\---



\## ⚙️ Configuration



Edit `config.yaml` to customize:



```yaml

dataset:

&#x20; sample\_size: 50        # number of test files



scanners:

&#x20; bandit:

&#x20;   enabled: true

&#x20; semgrep:

&#x20;   enabled: true

&#x20; pip\_audit:

&#x20;   enabled: true



leaderboard:

&#x20; rank\_by: "f1\_score"    # or precision, recall

```



\---



\## 🗺️ Roadmap



\- \[ ] Parallel scan execution (faster benchmarks)

\- \[ ] GitHub Actions CI integration

\- \[ ] CodeQL adapter

\- \[ ] Web dashboard for results

\- \[ ] AI model comparison (GPT-4 vs Claude vs Gemini

&#x20;     generated code vulnerability rates)



\---



\## 🤝 Contributing



1\. Fork the repo

2\. Add your scanner using `custom\_tool\_template.py`

3\. Submit a pull request with benchmark results



\---



\## 📚 Dataset



Vulnerable code samples sourced from

\[cmonplz/Python\_Vulnerability\_Remediation](https://huggingface.co/datasets/cmonplz/Python\_Vulnerability\_Remediation)

on HuggingFace — Python SAST vulnerability dataset

with CWE labels.



\---



\## 👤 Author



Built by \[@Ragnarok31](https://github.com/Ragnarok31)

as a learning project exploring AI code security

and static analysis tooling.



\---



\*If this project helped you, consider giving it a ⭐\*

