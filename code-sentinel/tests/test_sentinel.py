"""Testes da propria skill CODE SENTINEL.

Rodar (a partir da pasta da skill):
    python3 -m unittest discover -s tests -v        # ou: python3 -m pytest tests -q

Os testes end-to-end usam os projetos em tests/fixtures/ e pulam deps/SAST externos
(rede) para serem deterministicos; o resto roda offline.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SKILL = Path(__file__).resolve().parent.parent
SCRIPTS = SKILL / "scripts"
FIX = SKILL / "tests" / "fixtures"
VULN = FIX / "vulnerable-shop"
HEALTHY = FIX / "healthy-lib"
sys.path.insert(0, str(SCRIPTS))

import cis_score  # noqa: E402
import scan_patterns  # noqa: E402
import scan_secrets  # noqa: E402
from common import out_dir, save_evidence, save_findings, write_json  # noqa: E402

PLANTED_SECRETS = ["AKIAZ7XQ3MPL2KDN8RTW", "Sup3rS3cretPw", "fixture-fake-key-7c1e9a2b4d6f",
                   "super-secret-jwt-key-123"]


def run_sentinel(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPTS / "sentinel.py"), *args], capture_output=True, text=True,
                          timeout=600)


class PadlockAssets(unittest.TestCase):
    def test_five_levels_svg_and_transparent_png(self):
        for lv in range(1, 6):
            svg = SKILL / "assets" / "padlocks" / f"level-{lv}.svg"
            png = SKILL / "assets" / "padlocks" / f"level-{lv}.png"
            self.assertTrue(svg.exists(), svg)
            self.assertIn("<svg", svg.read_text())
            self.assertTrue(png.exists(), png)
            head = png.read_bytes()[:26]
            self.assertEqual(head[:8], b"\x89PNG\r\n\x1a\n")
            self.assertEqual(head[25], 6, "PNG deve ser RGBA (fundo transparente)")


class SecretScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings, cls.ev = scan_secrets.scan(VULN)

    def test_detects_planted_secrets(self):
        rules = {f["rule_id"] for f in self.findings}
        for r in ("SECRET-AWS-ACCESS-KEY", "SECRET-DB-URL", "SECRET-HARDCODED"):
            self.assertIn(r, rules)
        self.assertTrue(any(f["file"] == "src/legacy/report.py" for f in self.findings))

    def test_provider_token_formats(self):
        # literais montados em tempo de execucao: nenhum token com formato real fica versionado
        samples = {
            "SECRET-STRIPE-KEY": "sk_" + "live_" + "Z" * 26,
            "SECRET-GITHUB-TOKEN": "gh" + "p_" + "a1B2" * 9,
            "SECRET-PRIVATE-KEY": "-----BEGIN " + "RSA PRIVATE KEY-----",
            "SECRET-AI-API-KEY": "sk-" + "ant-" + "x" * 30,
        }
        with tempfile.TemporaryDirectory() as td:
            for i, (rid, val) in enumerate(samples.items()):
                (Path(td) / f"cfg{i}.js").write_text(f"const v = '{val}';\n")
            found, _ = scan_secrets.scan(Path(td))
        rules = {f["rule_id"] for f in found}
        for rid, val in samples.items():
            self.assertIn(rid, rules)
            if rid != "SECRET-PRIVATE-KEY":
                self.assertNotIn(val, json.dumps(found))

    def test_never_leaks_secret_values(self):
        blob = json.dumps(self.findings)
        for s in PLANTED_SECRETS:
            self.assertNotIn(s, blob, f"segredo vazou no relatorio: {s[:4]}...")

    def test_all_confirmed_security(self):
        self.assertTrue(all(f["status"] == "confirmed" and f["category"] == "security" for f in self.findings))


class PatternScan(unittest.TestCase):
    def test_detects_planted_issues(self):
        findings, ev = scan_patterns.scan(VULN)
        rules = {f["rule_id"] for f in findings}
        expected = {
            "JS-SQL-INJECTION", "JS-CMD-INJECTION", "JS-EVAL", "JS-PATH-TRAVERSAL", "JS-ADMIN-ROUTE-NO-AUTH",
            "JS-WEAK-HASH", "JS-INSECURE-RANDOM", "JS-STACK-LEAK", "JS-SENSITIVE-LOG", "JS-JSON-PARSE-UNGUARDED",
            "JS-FOREACH-ASYNC", "JS-EMPTY-CATCH", "JS-UNBOUNDED-COLLECTION", "JS-INTERVAL-NO-CLEAR",
            "JS-DIV-BY-ZERO", "JS-UNDECLARED-DEPENDENCY", "GEN-DUPLICATE-CODE",
            "PY-SQL-INJECTION", "PY-SHELL", "PY-UNSAFE-DESERIALIZATION", "PY-BARE-EXCEPT",
            "PY-REQUESTS-NO-TIMEOUT", "PY-MUTABLE-DEFAULT",
        }
        self.assertFalse(expected - rules, f"nao detectados: {sorted(expected - rules)}")
        heuristic = [f for f in findings if f["rule_id"] != "JS-UNDECLARED-DEPENDENCY"]
        self.assertTrue(all(f["status"] == "potential" for f in heuristic), "heuristica nunca e 'confirmed'")
        self.assertIn("duplication", ev["checks"])

    def test_healthy_fixture_has_no_security_findings(self):
        findings, _ = scan_patterns.scan(HEALTHY)
        self.assertEqual([f for f in findings if f["category"] == "security"], [])
        self.assertEqual([f for f in findings if f["severity"] in ("CRITICAL", "HIGH")], [])

    def test_ignore_marker(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "a.js").write_text("const r = eval(x); // sentinel-ignore\nconst s = eval(y);\n")
            findings, _ = scan_patterns.scan(Path(td))
            evals = [f for f in findings if f["rule_id"] == "JS-EVAL"]
            self.assertEqual([f["line"] for f in evals], [2])


class Scoring(unittest.TestCase):
    """Cenarios sinteticos: validam regras de confianca, tetos e prontidao."""

    FULL_CHECKS = ["deps", "secrets", "sast", "sast_heuristic", "manual_security_review", "syntax", "lint",
                   "manual_logic_review", "error_handling_heuristic", "manual_error_review", "perf_heuristic",
                   "perf_tests", "manual_perf_review", "duplication", "complexity_heuristic", "format",
                   "manual_arch_review"]

    def make(self, checks, tests, findings=()):
        td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, td, True)
        d = out_dir(td, str(td / "out"))
        write_json(d / "stack.json", {"project": "sintetico", "is_typescript": False})
        save_evidence(d, "manual", {"checks": list(checks)})
        if tests is not None:
            save_evidence(d, "tests", tests)
        save_findings(d, "manual", list(findings))
        return cis_score.score(d)

    GREEN = {"executed": True, "framework": "jest", "total": 50, "passed": 50, "failed": 0, "skipped": 0,
             "coverage": {"lines": 92.0}, "test_files": 10,
             "edge_case_categories": ["vazio/nulo", "limites", "concorrencia", "falha externa"]}

    def test_no_evidence_scores_zero(self):
        s = self.make([], None)
        self.assertEqual(s["score"], 0)
        self.assertEqual(s["level"], 1)
        self.assertEqual(s["confidence_label"], "Baixa")

    def test_full_evidence_clean_reaches_level_5(self):
        s = self.make(self.FULL_CHECKS, self.GREEN)
        self.assertGreaterEqual(s["score"], 90)
        self.assertEqual(s["level"], 5)
        self.assertEqual(s["readiness"][-1]["status"], "APTO")

    def test_confirmed_critical_caps_at_59(self):
        crit = {"title": "SQLi", "severity": "CRITICAL", "status": "confirmed", "category": "security",
                "file": "a.js", "line": 1, "rule_id": "X"}
        s = self.make(self.FULL_CHECKS, self.GREEN, [crit])
        self.assertLessEqual(s["score"], 59)
        self.assertLessEqual(s["criteria"]["security"]["points"], 5)
        self.assertEqual(s["readiness"][-1]["status"], "NÃO APTO")
        self.assertEqual(s["readiness"][2]["status"], "NÃO APTO")  # homologacao

    def test_potential_critical_caps_at_74(self):
        crit = {"title": "SQLi?", "severity": "CRITICAL", "status": "potential", "category": "security",
                "file": "a.js", "line": 1, "rule_id": "X"}
        s = self.make(self.FULL_CHECKS, self.GREEN, [crit])
        self.assertLessEqual(s["score"], 74)

    def test_failing_tests_cap(self):
        t = dict(self.GREEN, passed=45, failed=5)
        s = self.make(self.FULL_CHECKS, t)
        self.assertLessEqual(s["score"], 74)

    def test_missing_tests_cap_and_production_blocked(self):
        t = {"executed": False, "test_files": 0, "reason": "sem testes"}
        s = self.make(self.FULL_CHECKS, t)
        self.assertLessEqual(s["score"], 74)
        self.assertEqual(s["criteria"]["tests"]["points"], 0)
        self.assertEqual(s["readiness"][-1]["status"], "NÃO APTO")

    def test_absence_of_findings_without_checks_is_not_rewarded(self):
        s = self.make(["secrets"], self.GREEN)
        self.assertLess(s["criteria"]["security"]["points"], 25 * 0.2)
        self.assertLessEqual(s["score"], 74)  # confianca de seguranca < 50%

    def test_triage_false_positive_removes_finding(self):
        f = {"title": "Rota admin", "severity": "HIGH", "status": "potential", "category": "security",
             "file": "a.js", "line": 9, "rule_id": "JS-ADMIN-ROUTE-NO-AUTH"}
        fp = {"title": "protegida", "status": "false_positive", "category": "security", "file": "a.js", "line": 9,
              "justification": "app.use(auth) global"}
        before = self.make(self.FULL_CHECKS, self.GREEN, [f])
        after = self.make(self.FULL_CHECKS, self.GREEN, [f, fp])
        self.assertEqual(before["findings_total"], 1)
        self.assertEqual(after["findings_total"], 0)
        self.assertGreater(after["score"], before["score"])
        self.assertEqual(after["findings_resolved_by_triage"][0]["triage"], "false_positive")


class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.listing_before = sorted(str(p.relative_to(VULN)) for p in VULN.rglob("*"))
        cls.tmp = Path(tempfile.mkdtemp())
        cls.vout = cls.tmp / "vuln"
        cls.hout = cls.tmp / "healthy"
        cls.rv = run_sentinel("audit", str(VULN), "--run-tests", "--skip", "deps,sast", "--out", str(cls.vout))
        cls.rh = run_sentinel("audit", str(HEALTHY), "--run-tests", "--skip", "deps,sast", "--out", str(cls.hout))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, True)

    def test_vulnerable_project_is_level_1(self):
        self.assertEqual(self.rv.returncode, 0, self.rv.stderr)
        s = json.loads((self.vout / "score.json").read_text())
        self.assertLessEqual(s["score"], 39)
        self.assertEqual(s["level"], 1)
        self.assertGreaterEqual(s["by_severity"]["CRITICAL"], 3)
        t = s["tests"]
        self.assertTrue(t["executed"])
        self.assertEqual(t["failed"], 2, "os 2 bugs plantados em pricing.js devem falhar nos testes")
        self.assertLess(t["coverage"]["lines"], 50, "cobertura efetiva deve contar arquivos nunca carregados")
        rules = {f.get("rule_id") for f in json.loads((self.vout / "findings-merged.json").read_text())["findings"]}
        self.assertIn("SYNTAX-ERROR", rules)

    def test_audit_leaves_no_files_in_audited_project(self):
        after = sorted(str(p.relative_to(VULN)) for p in VULN.rglob("*"))
        self.assertEqual(after, self.listing_before)

    def test_reports_generated_with_padlock(self):
        md = (self.vout / "report.md").read_text()
        for needle in ("CODE SENTINEL — RELATÓRIO DE INTEGRIDADE", "CODE INTEGRITY SCORE:", "NÍVEL DE PROTEÇÃO:",
                       "padlock-level-1.png", "Parecer final", "Ferramentas utilizadas"):
            self.assertIn(needle, md)
        self.assertTrue((self.vout / "padlock-level-1.png").exists())
        html = (self.vout / "report.html").read_text()
        self.assertIn("<svg", html)
        for s in PLANTED_SECRETS:
            self.assertNotIn(s, md)
            self.assertNotIn(s, html)

    def test_skipped_tools_are_reported_with_reason(self):
        tools = json.loads((self.vout / "evidence" / "tools.json").read_text())["tools"]
        self.assertTrue(all(t["reason"] for t in tools if t["status"] != "executed"))

    def test_healthy_project_scores_higher_without_blockers(self):
        self.assertEqual(self.rh.returncode, 0, self.rh.stderr)
        s = json.loads((self.hout / "score.json").read_text())
        v = json.loads((self.vout / "score.json").read_text())
        self.assertGreater(s["score"], v["score"] + 25)
        self.assertEqual(s["by_severity"]["CRITICAL"] + s["by_severity"]["HIGH"], 0)
        self.assertEqual(s["tests"]["failed"], 0)
        self.assertEqual(s["criteria"]["tests"]["points"], 20)
        stages = {r["stage"]: r for r in s["readiness"]}
        self.assertEqual(stages["Testes (QA)"]["status"], "APTO")
        # com deps/SAST pulados, o unico bloqueio de homologacao pode ser a nota (falta de verificacao)
        self.assertTrue(all(x.startswith("CIS") for x in stages["Homologação"]["reasons"])
                        or stages["Homologação"]["status"] == "APTO", stages["Homologação"])
        self.assertEqual(stages["Produção"]["status"], "NÃO APTO", "sem deps/SAST auditados nao pode ir para producao")

    def test_manual_review_evidence_raises_confidence_via_rescore(self):
        before = json.loads((self.hout / "score.json").read_text())
        (self.hout / "evidence" / "manual.json").write_text(json.dumps({
            "checks": ["manual_security_review", "manual_logic_review", "manual_error_review",
                       "manual_perf_review", "manual_arch_review"],
            "summary": "Biblioteca pura, sem I/O; entradas validadas na fronteira."}))
        r = run_sentinel("rescore", str(HEALTHY), "--out", str(self.hout))
        self.assertEqual(r.returncode, 0, r.stderr)
        after = json.loads((self.hout / "score.json").read_text())
        self.assertGreater(after["score"], before["score"])
        self.assertGreaterEqual(after["level"], 3)
        self.assertEqual({r["stage"]: r["status"] for r in after["readiness"]}["Homologação"], "APTO")
        self.assertIn("Biblioteca pura", (self.hout / "report.md").read_text())

    def test_snapshot_and_compare(self):
        run_sentinel("snapshot", str(VULN), "antes", "--out", str(self.vout))
        r = run_sentinel("compare", str(VULN), "antes", "--out", str(self.vout))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("CODE INTEGRITY SCORE", (self.vout / "comparison.md").read_text())


if __name__ == "__main__":
    unittest.main()
