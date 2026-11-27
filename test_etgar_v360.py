#!/usr/bin/env python3
"""
test_etgar_v360.py — Athena's Acceptance & Adversarial Suites (V36.0.2)
Covers:
  - Suite A: Security, SSRF, DNS overflow rejection (16+17th private IP), live TLS hostname verification, XSS/Prompt Injection
  - Suite B: RFC 8785 JCS conformance, NFC != NFD, strict UTF-8 & BOM rejection, distinct diagnostic error codes
  - Suite D: Selection Bias smoke test, Clean Article Challenge, visible RETRACTED_SOURCE, tri-state retraction status (Europe PMC / OpenAlex / RSS)
  - Suite G: HTTP errors, crash-safe PID lockfile, atomic write, CollectionBudget enforcement (Athena's 144-candidate simulation), single-source-of-truth config, and hard deadline checks before & after rate-limit sleep
"""

import copy
import datetime
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

import etgar_scout as es


class TestSuiteA_SecurityAndBoundaries(unittest.TestCase):
    def setUp(self):
        self.allowlist = ["api.openalex.org", "www.hayadan.org.il"]
        self.policy = {
            "https_only": True,
            "allowed_ports": [443],
            "block_url_credentials": True,
            "max_redirects": 3,
            "max_response_bytes": 1024 * 64,
            "request_timeout_sec": 5,
            "max_dns_records": 16,
        }

    def test_A01_special_and_private_ipv4_ipv6_and_mapped_blocked(self):
        blocked_ips = [
            "127.0.0.1", "10.0.0.5", "172.16.0.1", "192.168.1.1",
            "169.254.169.254", "100.64.0.1", "192.0.2.1", "224.0.0.1", "0.0.0.0",
            "::1", "::", "fe80::1", "fc00::1", "ff02::1",
            "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",
        ]
        for addr in blocked_ips:
            self.assertFalse(es.is_public_ip(addr), f"Non-public IP should be blocked: {addr}")
        self.assertTrue(es.is_public_ip("93.184.216.34"))
        self.assertTrue(es.is_public_ip("2606:2800:220:1:248:1893:25c8:1946"))

        with self.assertRaises(es.SecurityBlockError):
            es.validate_url_policy("https://localhost/secret", self.allowlist, self.policy)

    def test_A02_file_scheme_http_credentials_and_non443_port_blocked(self):
        pub_dns = lambda h, p: ["93.184.216.34"]
        for bad_url in [
            "file:///etc/passwd",
            "http://api.openalex.org/works",
            "https://user:pass@api.openalex.org/works",
            "https://api.openalex.org:8443/works",
            "https://evil.example/works",
            "https://127.0.0.1/works",
        ]:
            with self.assertRaises(es.SecurityBlockError, msg=f"Should block {bad_url}"):
                es.validate_url_policy(bad_url, self.allowlist, self.policy, dns_resolver=pub_dns)

    def test_A03_dns_multi_record_and_overflow_17th_ip_rejected(self):
        """Athena Checklist #1 (Adversarial): >16 DNS records (including 16 public + 17th 127.0.0.1) MUST be REJECTED, never sliced."""
        mixed_dns = lambda h, p: ["93.184.216.34", "::ffff:192.168.0.10"]
        with self.assertRaises(es.SecurityBlockError):
            es.validate_url_policy("https://api.openalex.org/works", self.allowlist, self.policy, dns_resolver=mixed_dns)

        # Athena's exact adversarial case: 16 public IPs + 17th is 127.0.0.1
        public_16 = [f"93.184.216.{i}" for i in range(1, 17)]
        dns_16_plus_loopback = lambda h, p: public_16 + ["127.0.0.1"]
        with self.assertRaises(es.SecurityBlockError):
            es.validate_url_policy("https://api.openalex.org/works", self.allowlist, self.policy, dns_resolver=dns_16_plus_loopback)

        # Even 17 public IPs MUST be rejected when max_dns_records == 16
        dns_17_public = lambda h, p: public_16 + ["93.184.216.17"]
        with self.assertRaises(es.SecurityBlockError):
            es.validate_url_policy("https://api.openalex.org/works", self.allowlist, self.policy, dns_resolver=dns_17_public)

        # Exactly 16 public IPs is permitted
        _p, _h, _port, ips = es.validate_url_policy("https://api.openalex.org/works", self.allowlist, self.policy, dns_resolver=lambda h, p: public_16)
        self.assertEqual(len(ips), 16)

    def test_A04_redirect_revalidation_host_header_and_dns_rebinding_between_requests(self):
        seen_calls = []

        def fake_dns_rebinding(host, port):
            if len(seen_calls) == 0:
                return ["93.184.216.34"]
            return ["127.0.0.1"]

        def transport_ok(url, pinned_ip, port, headers):
            seen_calls.append((url, pinned_ip, headers["Host"]))
            return 200, {}, b'{"ok":true}'

        _final_u, status, _body = es.safe_fetch_bytes(
            "https://api.openalex.org/works",
            self.allowlist,
            self.policy,
            dns_resolver=fake_dns_rebinding,
            transport_override=transport_ok,
        )
        self.assertEqual(status, 200)
        self.assertEqual(seen_calls[0][1], "93.184.216.34")
        self.assertEqual(seen_calls[0][2], "api.openalex.org")

        with self.assertRaises(es.SecurityBlockError):
            es.safe_fetch_bytes(
                "https://api.openalex.org/works",
                self.allowlist,
                self.policy,
                dns_resolver=fake_dns_rebinding,
                transport_override=transport_ok,
            )

        pub_dns = lambda h, p: ["93.184.216.34"] if h == "api.openalex.org" else ["10.0.0.1"]
        with self.assertRaises(es.SecurityBlockError):
            es.safe_fetch_bytes(
                "https://api.openalex.org/works",
                self.allowlist,
                self.policy,
                dns_resolver=pub_dns,
                transport_override=lambda u, i, p, h: (302, {"location": "https://127.0.0.1/admin"}, b""),
            )
        with self.assertRaises(es.SecurityBlockError):
            es.safe_fetch_bytes(
                "https://api.openalex.org/works",
                self.allowlist,
                self.policy,
                dns_resolver=pub_dns,
                transport_override=lambda u, i, p, h: (301, {"location": "https://attacker.example/payload"}, b""),
            )

        conn = es.PinnedHTTPSConnection("api.openalex.org", "93.184.216.34", 443, 5, ssl.create_default_context())
        with self.assertRaises(es.SecurityBlockError):
            conn.set_tunnel("evil.example")

    def test_A05_live_tls_hostname_verification_on_pinned_ip(self):
        openssl_bin = shutil.which("openssl")
        if not openssl_bin:
            self.skipTest("openssl binary not installed in this environment")

        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)

            def _make_cert(prefix: str, san: str):
                key_p = tdp / f"{prefix}.key"
                crt_p = tdp / f"{prefix}.crt"
                cmd = [
                    openssl_bin, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key_p), "-out", str(crt_p),
                    "-days", "1", "-subj", f"/CN={prefix}.test",
                    "-addext", f"subjectAltName={san}",
                ]
                proc = subprocess.run(cmd, capture_output=True, text=True)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                return key_p, crt_p

            good_key, good_crt = _make_cert("good", "DNS:api.openalex.org")
            wrong_key, wrong_crt = _make_cert("wrong", "DNS:wrong.example.org,IP:127.0.0.1")

            def _serve_once(key_path: Path, crt_path: Path):
                srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                srv_ctx.load_cert_chain(certfile=str(crt_path), keyfile=str(key_path))
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind(("127.0.0.1", 0))
                port = srv.getsockname()[1]
                srv.listen(1)

                def _worker():
                    try:
                        raw_c, _ = srv.accept()
                        try:
                            with srv_ctx.wrap_socket(raw_c, server_side=True) as tls_c:
                                tls_c.recv(1024)
                                tls_c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                        except Exception:
                            pass
                        finally:
                            raw_c.close()
                    finally:
                        srv.close()

                th = threading.Thread(target=_worker, daemon=True)
                th.start()
                return port, th

            port1, th1 = _serve_once(good_key, good_crt)
            cli_ctx1 = ssl.create_default_context(cafile=str(good_crt))
            conn1 = es.PinnedHTTPSConnection("api.openalex.org", "127.0.0.1", port1, timeout=5, context=cli_ctx1)
            try:
                conn1.request("GET", "/works", headers={"Host": "api.openalex.org", "Connection": "close"})
                resp1 = conn1.getresponse()
                self.assertEqual(resp1.status, 200)
                self.assertEqual(resp1.read(), b"OK")
            finally:
                conn1.close()
                th1.join(timeout=2)

            port2, th2 = _serve_once(wrong_key, wrong_crt)
            cli_ctx2 = ssl.create_default_context(cafile=str(wrong_crt))
            conn2 = es.PinnedHTTPSConnection("api.openalex.org", "127.0.0.1", port2, timeout=5, context=cli_ctx2)
            try:
                with self.assertRaises(ssl.SSLCertVerificationError):
                    conn2.request("GET", "/works", headers={"Host": "api.openalex.org", "Connection": "close"})
            finally:
                conn2.close()
                th2.join(timeout=2)

    def test_A06_prompt_injection_xss_and_path_traversal_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = json.loads(Path("etgar_config.json").read_text(encoding="utf-8"))
            cfg["output_dir"] = td
            cfg_path = Path(td) / "cfg.json"
            cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
            _jp, _sp, hp, doc = es.run_scout(cfg_path, demo_mode=True)
            html_out = hp.read_text(encoding="utf-8")
            self.assertIn("Content-Security-Policy", html_out)
            self.assertNotIn("<script>alert(1)</script>", html_out)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html_out)
            inj_items = [it for it in doc["payload"]["items"] if it["signals"]["untrusted_injection_pattern_detected"]]
            self.assertGreaterEqual(len(inj_items), 1)

            for bad_name in ["../escape.json", "/etc/evil.json", "..\\win.json", "sub/nested.json"]:
                with self.assertRaises(es.SecurityBlockError):
                    es.resolve_safe_output_path(Path(td), bad_name)


class TestSuiteB_RFC8785JCSAndDiagnosticIntegrity(unittest.TestCase):
    def test_B01_official_rfc8785_jcs_numbers_utf16_keys_and_unicode_nfc_nfd(self):
        num_vectors = [
            (0.0, "0"), (-0.0, "0"), (1.0, "1"), (1e-5, "0.00001"), (1e-6, "0.000001"),
            (1e-7, "1e-7"), (1e20, "100000000000000000000"), (1e21, "1e+21"),
            (333333333.33333329, "333333333.3333333"), (4.50, "4.5"), (5e-324, "5e-324"),
        ]
        for val, exp in num_vectors:
            self.assertEqual(es.jcs_format_number(val), exp)

        rfc_obj = {
            "\u20ac": "Euro Sign",
            "\r": "Carriage Return",
            "1": "One",
            "\u0080": "Control",
            "\ufb33": "Hebrew Letter Dalet With Dagesh",
            "\U0001f600": "Emoji: Grinning Face",
            "\u00f6": "Latin Small Letter O With Diaeresis",
        }
        got_jcs = es.jcs_serialize_str(rfc_obj)
        expected_jcs = (
            '{"\\r":"Carriage Return","1":"One","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis",'
            '"\u20ac":"Euro Sign","\U0001f600":"Emoji: Grinning Face","\ufb33":"Hebrew Letter Dalet With Dagesh"}'
        )
        self.assertEqual(got_jcs, expected_jcs)

        nfc_bytes = es.canonical_json_bytes({"k": "caf\u00e9"})
        nfd_bytes = es.canonical_json_bytes({"k": "cafe\u0301"})
        self.assertNotEqual(nfc_bytes, nfd_bytes)
        self.assertNotEqual(es.sha256_bytes(nfc_bytes), es.sha256_bytes(nfd_bytes))

    def test_B02_distinct_diagnostic_error_modes_including_invalid_utf8(self):
        payload = {"run_id": "R1", "items": [{"title": "Bianfu Cave"}]}
        signed = es.build_signed_briefing(payload)
        valid_bytes = (json.dumps(signed, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        valid_sidecar = f"{es.sha256_bytes(valid_bytes)}  brief.json\n"

        self.assertEqual(es.verify_briefing_bytes(valid_bytes, valid_sidecar)["code"], "OK")
        self.assertEqual(es.verify_briefing_bytes(valid_bytes, ("0" * 64) + "  brief.json\n")["code"], "SIDECAR_FILE_SHA256_MISMATCH")
        self.assertEqual(es.verify_briefing_bytes(valid_bytes.replace(b"Bianfu Cave", b"Bianpu Cave"))["code"], "PAYLOAD_SHA256_MISMATCH")
        self.assertEqual(es.verify_briefing_bytes(es.UTF8_BOM + valid_bytes)["code"], "UTF8_BOM_DETECTED")
        self.assertEqual(es.verify_briefing_bytes(b"\xff\xfe\x80invalid")["code"], "INVALID_UTF8_ENCODING")

        bad_schema = copy.deepcopy(signed)
        bad_schema["schema"] = "unknown_v9"
        self.assertEqual(es.verify_briefing_bytes(json.dumps(bad_schema).encode("utf-8"))["code"], "SCHEMA_VALIDATION_ERROR")
        self.assertEqual(es.verify_briefing_bytes(b"{broken json")["code"], "JSON_SYNTAX_ERROR")

    def test_B03_duplicate_content_across_two_urls_preserves_both_sources(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = json.loads(Path("etgar_config.json").read_text(encoding="utf-8"))
            cfg["output_dir"] = td
            cfg_path = Path(td) / "cfg.json"
            cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
            jp, sp, _hp, doc = es.run_scout(cfg_path, demo_mode=True)

            ver = es.verify_briefing_bytes(jp.read_bytes(), sp.read_text(encoding="utf-8"))
            self.assertTrue(ver["ok"])
            self.assertTrue(ver["sidecar_verified"])

            w1001 = [it for it in doc["payload"]["items"] if "Revised luminescence chronology" in it["title"]]
            self.assertEqual(len(w1001), 1)
            self.assertIn(
                "https://www.sciencedaily.com/releases/2026/11/mirror-w1001.htm",
                w1001[0]["provenance"]["duplicate_source_urls"],
            )


class TestSuiteD_SelectionSmokeCleanChallengeAndTriStateRetraction(unittest.TestCase):
    def _build_balanced_corpus(self):
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        def mk(sid, title, body, url, stype="peer_reviewed_or_preprint_metadata", topic="t"):
            raw = f"{title}\n\n{body}"
            return {
                "original_url": url, "final_url": url, "fetched_at": now,
                "source_id": sid, "source_title": title, "publisher": sid,
                "source_type": stype, "publication_date": now[:10], "doi": "", "pmid": "",
                "is_retracted": False, "retraction_status": "NOT_RETRACTED",
                "retraction_check_method": "test_fixture",
                "raw_text": raw, "raw_content_sha256": es.sha256_text_utf8(raw),
                "extractor_version": es.EXTRACTOR_VERSION, "topic": topic, "query_used": "q",
            }

        random_pool = []
        for i in range(10):
            title = f"Breakthrough miracle theory collapses in study {i}" if i % 2 == 0 else f"Calibration report on mineral isotope sample {i}"
            src = "big_source" if i < 6 else f"small_source_{i}"
            random_pool.append(mk(src, title, f"Measured n={40+i} specimens with standard calibration controls.", f"https://api.openalex.org/works/R{i}"))

        interest_pool = [
            mk("big_source", "Clean neutral stratigraphy study A", "Detailed quartz OSL sample measurements across 8 strata.", "https://api.openalex.org/works/I1", topic="paleo"),
            mk("big_source", "Breakthrough shocking paleo discovery B", "Preliminary fragment analysis with sensational headline.", "https://api.openalex.org/works/I2", topic="paleo"),
            mk("small_source", "Neutral paleoclimate pollen series C", "Pollen core percentages across 12 horizons.", "https://api.openalex.org/works/I3", topic="paleo"),
        ]
        counter_pool = [
            mk("openalex", "Systematic review and replication of claim X showing null effect", "Pooled d=0.02 across 12 preregistered replications.", "https://api.openalex.org/works/C1"),
        ]
        discovery_pool = [
            mk("small_disc", "Hydrothermal vent manganese oxidation rates", "Measured in situ across 5 deep-sea vents.", "https://api.openalex.org/works/D1"),
        ]
        return {"interest": interest_pool, "counter": counter_pool, "random": random_pool, "discovery": discovery_pool}

    def test_D01_selection_bias_smoke_test_within_declared_frame(self):
        """
        SMOKE TEST ONLY (per Athena's audit): verifies coarse anti-monopoly diversity,
        QUERY_BASED_COUNTER non-semantic tagging, and absence of gross sensationalism boosting
        across 30 seeds within a synthetic frame. Does NOT constitute a general statistical
        proof of unbiased sampling across external corpora.
        """
        cfg = json.loads(Path("etgar_config.json").read_text(encoding="utf-8"))
        cands = self._build_balanced_corpus()
        p = es.run_selection_pipeline(cands, [], cfg, "cfgsha", "RUN-D1", "2026-11-24|seed1")

        int_items = [it for it in p["items"] if it["track"] == "interest"]
        self.assertEqual(len(int_items), 2)
        self.assertEqual({it["provenance"]["source_id"] for it in int_items}, {"big_source", "small_source"})

        cnt_items = [it for it in p["items"] if it["track"] == "counter"]
        self.assertEqual(len(cnt_items), 1)
        self.assertEqual(cnt_items[0]["counter_mode"], "QUERY_BASED_COUNTER")
        self.assertEqual(cnt_items[0]["semantic_status"], "NOT_ASSESSED")

        sens_total = neut_total = 0
        for s in range(30):
            ps = es.run_selection_pipeline({"interest": [], "counter": [], "random": cands["random"], "discovery": []}, [], cfg, "cfgsha", f"R{s}", f"seed-{s}")
            for it in ps["items"]:
                if it["signals"]["sensational_headline_Lexicon"]:
                    sens_total += 1
                else:
                    neut_total += 1
        ratio = sens_total / (sens_total + neut_total)
        self.assertTrue(0.25 <= ratio <= 0.75, f"Smoke test detected coarse sensational bias: ratio={ratio}")

        cfg2 = copy.deepcopy(cfg)
        cfg2["tracks"]["interest"]["queries"] = []
        p_a = es.run_selection_pipeline(cands, [], cfg, "cfgsha", "RA", "fixed-seed")
        p_b = es.run_selection_pipeline(cands, [], cfg2, "cfgsha", "RB", "fixed-seed")
        self.assertEqual(
            [it["item_id"] for it in p_a["items"] if it["track"] in ("random", "discovery")],
            [it["item_id"] for it in p_b["items"] if it["track"] in ("random", "discovery")],
        )
        self.assertFalse(p_a["auto_learn_from_clicks"])

    def test_D02_clean_article_challenge_and_retracted_source_visibility(self):
        cfg = json.loads(Path("etgar_config.json").read_text(encoding="utf-8"))
        cands, cov = es.build_demo_corpus(datetime.datetime.now(datetime.timezone.utc).isoformat())
        p = es.run_selection_pipeline(cands, cov, cfg, "cfgsha", "RUN-CLEAN", "2026-11-24|clean")

        self.assertGreaterEqual(p["selection_audit"]["clean_neutral_items_presented"], 5)
        for it in p["items"]:
            self.assertEqual(it["signals"]["background_statistical_verdict"], "NONE (V36.0 Scout does not adjudicate)")
            self.assertEqual(it["verification_axes"]["PRIMARY_SOURCE_VERIFICATION"]["status"], "NOT_VERIFIED")
            self.assertIn(it["retraction_status"], ("NOT_RETRACTED", "UNKNOWN"))

        ret_list = p["retracted_sources"]
        self.assertEqual(len(ret_list), 1)
        self.assertEqual(ret_list[0]["source_status"], "RETRACTED_SOURCE")
        self.assertEqual(ret_list[0]["retraction_status"], "RETRACTED")
        self.assertTrue(ret_list[0]["retraction_notice"])
        self.assertEqual(p["selection_audit"]["retracted_sources_flagged"], 1)

        html_str = es.render_morning_briefing_html(es.build_signed_briefing(p))
        self.assertIn("RETRACTED_SOURCE", html_str)
        self.assertIn("RETRACTION_STATUS: UNKNOWN", html_str)

    def test_D03_europepmc_openalex_rss_tri_state_retraction_status(self):
        """Athena Checklist #5 (Adversarial): Europe PMC retraction detection + tri-state UNKNOWN when unverified."""
        epmc_meta = {"id": "europepmc", "name": "Europe PMC", "source_type": "biomedical_life_sciences_abstract"}
        now = "2026-11-24T00:00:00Z"

        # 1. Athena's exact adversarial record with is_retracted: True, plus pubTypeList Retracted Publication, plus unverified record
        epmc_payload = json.dumps({
            "resultList": {
                "result": [
                    {"title": "Study with explicit flag", "abstractText": "Sample text A.", "pmid": "111", "is_retracted": True},
                    {"title": "Study with pubTypeList retraction", "abstractText": "Sample text B.", "pmid": "222", "pubTypeList": {"pubType": ["Journal Article", "Retracted Publication"]}},
                    {"title": "Study without retraction check", "abstractText": "Sample text C.", "pmid": "333"},
                ]
            }
        }).encode("utf-8")

        parsed_no_checker = es.parse_europepmc_response(epmc_payload, epmc_meta, "https://www.ebi.ac.uk/x", now, retraction_checker=None)
        self.assertEqual(parsed_no_checker[0]["retraction_status"], "RETRACTED")
        self.assertTrue(parsed_no_checker[0]["is_retracted"])
        self.assertEqual(parsed_no_checker[1]["retraction_status"], "RETRACTED")
        self.assertTrue(parsed_no_checker[1]["is_retracted"])
        # Without status check, record #3 MUST be UNKNOWN, never silently NOT_RETRACTED!
        self.assertEqual(parsed_no_checker[2]["retraction_status"], "UNKNOWN")
        self.assertFalse(parsed_no_checker[2]["is_retracted"])

        # 2. With status checker returning verified NOT_RETRACTED vs RETRACTED vs UNKNOWN on failure
        parsed_checked = es.parse_europepmc_response(
            epmc_payload, epmc_meta, "https://www.ebi.ac.uk/x", now,
            retraction_checker=lambda pmid, doi: ("NOT_RETRACTED", "mock_epmc_status_api") if pmid == "333" else ("UNKNOWN", "err"),
        )
        self.assertEqual(parsed_checked[2]["retraction_status"], "NOT_RETRACTED")

        # 3. check_europepmc_retraction_status live helper tested via mock fetch_fn
        allowlist = ["www.ebi.ac.uk"]
        policy = {"https_only": True, "allowed_ports": [443], "max_redirects": 2, "max_response_bytes": 65536, "request_timeout_sec": 5, "max_dns_records": 16}

        st_ret, _ = es.check_europepmc_retraction_status(
            "12345", "", allowlist, policy,
            fetch_fn=lambda u, a, p, timeout_override=None: (u, 200, json.dumps({"resultList": {"result": [{"pmid": "12345", "pubTypeList": {"pubType": ["Retracted Publication"]}}]}}).encode("utf-8")),
        )
        self.assertEqual(st_ret, "RETRACTED")

        st_ok, _ = es.check_europepmc_retraction_status(
            "12345", "", allowlist, policy,
            fetch_fn=lambda u, a, p, timeout_override=None: (u, 200, json.dumps({"resultList": {"result": [{"pmid": "12345", "pubTypeList": {"pubType": ["Journal Article"]}}]}}).encode("utf-8")),
        )
        self.assertEqual(st_ok, "NOT_RETRACTED")

        def _failing_fetch(*args, **kwargs):
            raise RuntimeError("network down")
        st_fail, _ = es.check_europepmc_retraction_status("12345", "", allowlist, policy, fetch_fn=_failing_fetch)
        self.assertEqual(st_fail, "UNKNOWN")

        # 4. OpenAlex missing is_retracted -> UNKNOWN; RSS -> ALWAYS UNKNOWN
        oa_raw = json.dumps({"results": [{"display_name": "OpenAlex missing flag work"}]}).encode("utf-8")
        oa_items = es.parse_openalex_response(oa_raw, {"id": "openalex", "name": "OpenAlex"}, "https://api.openalex.org/w", now)
        self.assertEqual(oa_items[0]["retraction_status"], "UNKNOWN")

        rss_raw = b"<rss><channel><item><title>RSS Article Title Here</title><description>RSS body description text here.</description><link>https://www.hayadan.org.il/a</link></item></channel></rss>"
        rss_items = es.parse_rss_response(rss_raw, {"id": "hayadan_rss", "name": "Hayadan"}, "https://www.hayadan.org.il/feed", now)
        self.assertEqual(rss_items[0]["retraction_status"], "UNKNOWN")


class TestSuiteG_ResilienceBudgetsAndDeadlineGuards(unittest.TestCase):
    def setUp(self):
        self.allowlist = ["api.openalex.org"]
        self.policy = {
            "https_only": True,
            "allowed_ports": [443],
            "block_url_credentials": True,
            "max_redirects": 2,
            "max_response_bytes": 1024,
            "request_timeout_sec": 5,
            "max_dns_records": 16,
        }
        self.pub_dns = lambda h, p: ["93.184.216.34"]

    def test_G01_http_429_500_oversized_and_redirect_loop_handled_cleanly(self):
        with self.assertRaises(es.ResourceLimitError):
            es.safe_fetch_bytes("https://api.openalex.org/w", self.allowlist, self.policy, self.pub_dns, lambda u, i, p, h: (429, {}, b"slow down"))
        with self.assertRaises(es.ResourceLimitError):
            es.safe_fetch_bytes("https://api.openalex.org/w", self.allowlist, self.policy, self.pub_dns, lambda u, i, p, h: (500, {}, b"err"))
        with self.assertRaises(es.ResourceLimitError):
            es.safe_fetch_bytes("https://api.openalex.org/w", self.allowlist, self.policy, self.pub_dns, lambda u, i, p, h: (200, {}, b"X" * 2048))
        with self.assertRaises(es.ResourceLimitError):
            es.safe_fetch_bytes("https://api.openalex.org/a", self.allowlist, self.policy, self.pub_dns, lambda u, i, p, h: (302, {"location": "https://api.openalex.org/a"}, b""))

    def test_G02_live_lock_blocks_parallel_run_and_dead_lock_recovers_with_audit(self):
        with tempfile.TemporaryDirectory() as td:
            lock_path = Path(td) / "etgar_scout.lock"
            l1 = es.CrashSafeLock(lock_path, "RUN-1", pid_checker=lambda pid: True)
            l1.acquire()
            try:
                l2 = es.CrashSafeLock(lock_path, "RUN-2", pid_checker=lambda pid: True)
                with self.assertRaises(es.LockConflictError):
                    l2.acquire()
            finally:
                l1.release()

            lock_path.write_text(json.dumps({"pid": 999999, "run_id": "CRASHED-RUN", "started_at": "2026-01-01T00:00:00Z"}), encoding="utf-8")
            l3 = es.CrashSafeLock(lock_path, "RUN-3", pid_checker=lambda pid: False)
            rec = l3.acquire()
            try:
                self.assertIsNotNone(rec)
                self.assertEqual(rec["event"], "STALE_LOCK_RECOVERED")
                self.assertEqual(rec["previous_lock"]["run_id"], "CRASHED-RUN")
            finally:
                l3.release()

    def test_G03_atomic_write_no_silent_overwrite_and_corrupt_xml_safe(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "brief.json"
            es.atomic_write_bytes(target, b'{"v":1}\n', overwrite=False)
            with self.assertRaises(FileExistsError):
                es.atomic_write_bytes(target, b'{"v":2}\n', overwrite=False)
            self.assertEqual(target.read_bytes(), b'{"v":1}\n')

        with self.assertRaises(Exception):
            es.parse_rss_response(b"<rss><broken><item>", {"id": "rss", "name": "RSS"}, "https://example.com", "2026-11-24")

    def test_G04_collection_budget_enforcement_athena_simulation(self):
        """
        Athena Checklist #2 & #3 (Adversarial Simulation):
        Replicates Athena's exact simulation where a misbehaving mock returns 12 items on every call across 4 sources & 12 queries.
        """
        base_cfg = json.loads(Path("etgar_config.json").read_text(encoding="utf-8"))
        call_counter = {"n": 0}

        def mock_fetcher_returns_12(src_meta, q, allowlist, policy, fetched_at, cap, timeout_override=None, retraction_checker=None):
            call_counter["n"] += 1
            batch = []
            for j in range(12):  # Deliberately ignores cap to test hard budget clamping!
                raw = f"Title {call_counter['n']}-{j}\n\nBody text for candidate {call_counter['n']}-{j} from {src_meta['id']}."
                batch.append({
                    "original_url": f"https://{src_meta['domain']}/item/{call_counter['n']}-{j}",
                    "final_url": f"https://{src_meta['domain']}/item/{call_counter['n']}-{j}",
                    "fetched_at": fetched_at, "source_id": src_meta["id"],
                    "source_title": f"Title {call_counter['n']}-{j}", "publisher": src_meta["id"],
                    "source_type": src_meta["source_type"], "publication_date": "2026-11-24",
                    "doi": "", "pmid": "", "is_retracted": False, "retraction_status": "UNKNOWN",
                    "raw_text": raw, "raw_content_sha256": es.sha256_text_utf8(raw),
                    "extractor_version": es.EXTRACTOR_VERSION,
                })
            return batch, None

        # Scenario 1 (Athena's exact setup): max_sources_per_run=1, max_items_per_source=12, max_total_candidates=80
        cfg1 = copy.deepcopy(base_cfg)
        cfg1["network_policy"]["max_sources_per_run"] = 1
        cfg1["network_policy"]["max_items_per_source"] = 12
        cfg1["network_policy"]["max_total_candidates"] = 80
        cfg1["network_policy"]["per_domain_delay_sec"] = 0
        cands1, cov1, bud1 = es.collect_live_candidates(cfg1, "2026-11-24T00:00:00Z", fetcher=mock_fetcher_returns_12, sleep_fn=lambda s: None)
        total1 = sum(len(v) for v in cands1.values())
        self.assertEqual(bud1["sources_used_count"], 1)
        self.assertEqual(total1, 12)
        self.assertEqual(bud1["total_candidates_collected"], 12)
        errors1 = {e.get("error") for e in cov1 if e.get("error")}
        self.assertIn("BUDGET_MAX_SOURCES_REACHED", errors1)
        self.assertIn("BUDGET_MAX_ITEMS_FOR_SOURCE_REACHED", errors1)

        # Scenario 2: max_sources_per_run=4, max_items_per_source=50, max_total_candidates=25 -> MUST stop at 25!
        cfg2 = copy.deepcopy(base_cfg)
        cfg2["network_policy"]["max_sources_per_run"] = 4
        cfg2["network_policy"]["max_items_per_source"] = 50
        cfg2["network_policy"]["max_total_candidates"] = 25
        cfg2["network_policy"]["per_domain_delay_sec"] = 0
        cands2, cov2, bud2 = es.collect_live_candidates(cfg2, "2026-11-24T00:00:00Z", fetcher=mock_fetcher_returns_12, sleep_fn=lambda s: None)
        total2 = sum(len(v) for v in cands2.values())
        self.assertEqual(total2, 25)
        self.assertEqual(bud2["total_candidates_collected"], 25)
        self.assertIn("BUDGET_MAX_TOTAL_CANDIDATES_REACHED", {e.get("error") for e in cov2 if e.get("error")})

    def test_G05_config_single_source_of_truth_and_version_alignment(self):
        """Athena Checklist #4 & #11: single per-track quota source of truth + aligned 36.0.2 versions."""
        cfg = json.loads(Path("etgar_config.json").read_text(encoding="utf-8"))
        self.assertEqual(cfg["config_version"], es.SCRIPT_VERSION)
        self.assertIn(es.SCRIPT_VERSION, cfg["network_policy"]["user_agent"])
        self.assertNotIn("max_selected_per_track", cfg["network_policy"])

        bad_cfg = copy.deepcopy(cfg)
        bad_cfg["network_policy"]["max_selected_per_track"] = 5
        with self.assertRaises(es.ConfigValidationError):
            es.validate_config(bad_cfg)

    def test_G06_deadline_checked_before_and_after_rate_limit_sleep(self):
        """Athena Checklist #12 (Adversarial): refuses to sleep past deadline, re-checks after sleep, and clamps request timeout."""
        cfg = json.loads(Path("etgar_config.json").read_text(encoding="utf-8"))
        cfg["network_policy"]["total_run_timeout_sec"] = 5.0
        cfg["network_policy"]["request_timeout_sec"] = 12.0
        cfg["network_policy"]["per_domain_delay_sec"] = 2.0

        # Fake clock starts at t=100.0 (deadline = 105.0)
        clock = {"t": 100.0}
        seen_timeouts = []
        sleeps = []

        def fake_clock():
            return clock["t"]

        def fake_sleep(sec):
            sleeps.append(sec)
            clock["t"] += sec

        def mock_fetch(src_meta, q, allowlist, policy, fetched_at, cap, timeout_override=None, retraction_checker=None):
            seen_timeouts.append(timeout_override)
            # Simulate a 3.5s request on first hit -> t becomes 103.5 (remaining = 1.5s < delay 2.0s!)
            clock["t"] += 3.5
            return [], None

        _c, cov, bud = es.collect_live_candidates(
            cfg, "2026-11-24T00:00:00Z",
            fetcher=mock_fetch, sleep_fn=fake_sleep, clock_fn=fake_clock,
        )
        # First request timeout MUST be clamped from 12.0s down to 5.0s!
        self.assertAlmostEqual(seen_timeouts[0], 5.0, places=2)
        # Second query hits same domain (api.openalex.org) with wait=2.0s > remaining=1.5s -> MUST NOT sleep past deadline!
        self.assertEqual(len(sleeps), 0)
        self.assertIn("TOTAL_RUN_TIMEOUT_REACHED_BEFORE_RATE_LIMIT_SLEEP", {e.get("error") for e in cov if e.get("error")})

        # Case 2: Sleep is allowed (wait=1.0s < remaining=2.0s), but OS sleep overshoots by +2.5s -> MUST re-check AFTER sleep!
        cfg_b = copy.deepcopy(cfg)
        cfg_b["network_policy"]["total_run_timeout_sec"] = 5.0
        cfg_b["network_policy"]["per_domain_delay_sec"] = 1.0
        clock_b = {"t": 200.0}
        calls_b = {"n": 0}
        def overshoot_sleep(sec):
            clock_b["t"] += sec + 2.5  # Overshoots deadline 205.0!
        def fast_fetch(src_meta, q, allowlist, policy, fetched_at, cap, timeout_override=None, retraction_checker=None):
            calls_b["n"] += 1
            clock_b["t"] += 3.0  # t=203.0, remaining=2.0 > wait=1.0
            return [], None
        _cb, cov_b, _bb = es.collect_live_candidates(
            cfg_b, "2026-11-24T00:00:00Z",
            fetcher=fast_fetch, sleep_fn=overshoot_sleep, clock_fn=lambda: clock_b["t"],
        )
        self.assertEqual(calls_b["n"], 1)
        self.assertIn("TOTAL_RUN_TIMEOUT_REACHED_AFTER_RATE_LIMIT_SLEEP", {e.get("error") for e in cov_b if e.get("error")})


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(__import__(__name__))
    runner = unittest.TextTestRunner(verbosity=2)
    res = runner.run(suite)
    raise SystemExit(0 if res.wasSuccessful() else 1)
