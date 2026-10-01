import re
import ipaddress
from typing import List, Dict, Any, Optional, Set, Tuple

# Strict banned words to prevent false-positive correlation on generic tokens
BANNED_GENERIC_TERMS: Set[str] = {
    # System & generic roles
    "system", "user", "admin", "administrator", "guest", "default", "everyone",
    "local service", "network service", "anonymous logon", "domain admins",
    "null", "none", "unknown", "n/a", "undefined", "-", "none", "nan",
    # OS & generic software
    "windows", "microsoft", "linux", "ubuntu", "chrome", "google",
    "file", "folder", "directory", "process", "image", "entry", "artifact",
    "event", "record", "socket", "network", "packet", "stream",
    # Local & non-routable terms
    "localhost", "loopback", "broadcasthost", "internal",
    # Common OS processes that are completely normal unless abnormal context
    "svchost.exe", "services.exe", "explorer.exe", "csrss.exe", "smss.exe",
    "wininit.exe", "taskhostw.exe", "system idle process", "conhost.exe", "registry"
}

RULE_SHARED_IP = "SHARED_IP"
RULE_SHARED_PROCESS = "SHARED_PROCESS"
RULE_SHARED_ACCOUNT = "SHARED_ACCOUNT"
RULE_SHARED_HASH = "SHARED_HASH"
RULE_SHARED_INDICATOR = "SHARED_INDICATOR"
RULE_SHARED_FORENSIC_OBJECT = "SHARED_FORENSIC_OBJECT"


class CorrelationEngine:
    """
    Deterministic Evidence Correlation Engine.
    Identifies and links structured forensic artifacts and findings across Disk, Memory, Malware, and Logs
    using explicit, deterministic rules and strict false-positive elimination.
    """

    def correlate_findings(
        self,
        findings: List[Dict[str, Any]],
        artifacts: Optional[List[Dict[str, Any]]] = None
    ) -> List[Dict[str, Any]]:
        """
        Executes deterministic correlation across structured forensic findings and artifacts.
        Guarantees explainable, reproducible, and duplicate-free relationship clusters.
        """
        if not findings and not artifacts:
            return []

        artifacts = artifacts or []

        # Map to track indicator -> matched finding IDs, artifact IDs, evidence IDs, and tools
        # Key: (rule, dimension, normalized_entity)
        clusters: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

        finding_parent_artifacts: Dict[str, Set[str]] = {}

        # 1. Index Indicators from Structured Findings
        for f in findings:
            f_id = f.get("id")
            ev_id = f.get("evidence_id")
            art_id = f.get("artifact_id")
            tool = f.get("tool") or f.get("source_tool") or "UnknownTool"

            if f_id and art_id:
                finding_parent_artifacts.setdefault(f_id, set()).add(art_id)

            extracted = self._extract_all_indicators(f, is_artifact=False)
            for rule, dimension, entity in extracted:
                key = (rule, dimension, entity)
                if key not in clusters:
                    clusters[key] = {
                        "rule": rule,
                        "dimension": dimension,
                        "entity": entity,
                        "finding_ids": set(),
                        "artifact_ids": set(),
                        "evidence_ids": set(),
                        "tools": set(),
                        "items": []
                    }
                if f_id:
                    clusters[key]["finding_ids"].add(f_id)
                if art_id:
                    clusters[key]["artifact_ids"].add(art_id)
                if ev_id:
                    clusters[key]["evidence_ids"].add(ev_id)
                clusters[key]["tools"].add(tool)
                clusters[key]["items"].append(f)

        # 2. Index Indicators from Structured Artifacts
        for a in artifacts:
            a_id = a.get("id")
            ev_id = a.get("evidence_id")
            tool = a.get("tool") or "UnknownTool"

            extracted = self._extract_all_indicators(a, is_artifact=True)
            for rule, dimension, entity in extracted:
                key = (rule, dimension, entity)
                if key not in clusters:
                    clusters[key] = {
                        "rule": rule,
                        "dimension": dimension,
                        "entity": entity,
                        "finding_ids": set(),
                        "artifact_ids": set(),
                        "evidence_ids": set(),
                        "tools": set(),
                        "items": []
                    }
                if a_id:
                    clusters[key]["artifact_ids"].add(a_id)
                if ev_id:
                    clusters[key]["evidence_ids"].add(ev_id)
                clusters[key]["tools"].add(tool)
                clusters[key]["items"].append(a)

        # 3. Filter and Build Valid Correlation Groups
        # Meaningful correlation requirement: must link at least 2 distinct forensic items:
        # - At least 2 distinct findings, OR
        # - At least 1 finding and at least 1 independent artifact, OR
        # - At least 2 independent artifacts
        correlated_groups = []
        for (rule, dimension, entity), data in clusters.items():
            f_ids = sorted(list(data["finding_ids"]))
            a_ids = sorted(list(data["artifact_ids"]))
            ev_ids = sorted(list(data["evidence_ids"]))
            tools = sorted(list(data["tools"]))

            # Enforce meaningful process corroboration (path, hash, cmdline, or cross-domain context)
            if rule == RULE_SHARED_PROCESS and not self._is_process_corroborated(data["items"], entity):
                continue

            parent_arts = set()
            for fid in f_ids:
                parent_arts.update(finding_parent_artifacts.get(fid, set()))
            independent_artifacts = set(a_ids) - parent_arts

            is_valid_correlation = (
                len(f_ids) >= 2 or
                (len(f_ids) >= 1 and len(independent_artifacts) >= 1) or
                len(independent_artifacts) >= 2
            )
            if not is_valid_correlation:
                continue

            confidence = self._calculate_confidence(rule, len(f_ids), len(tools))
            title, description = self._generate_explanation(rule, entity, len(f_ids), len(a_ids), tools)

            correlated_groups.append({
                "rule": rule,
                "dimension": dimension,
                "correlated_entity": entity,
                "title": title,
                "description": description,
                "tools_involved": tools,
                "supporting_finding_ids": f_ids,
                "supporting_artifact_ids": a_ids,
                "supporting_evidence_ids": ev_ids,
                "correlation_confidence": confidence
            })

        # Deterministic sort order by rule, dimension, then entity
        correlated_groups.sort(key=lambda g: (g["rule"], g["dimension"], g["correlated_entity"]))
        return correlated_groups

    def _extract_all_indicators(self, item: Dict[str, Any], is_artifact: bool = False) -> Set[Tuple[str, str, str]]:
        """
        Extracts all valid, non-banned indicators from a finding or artifact record.
        """
        indicators: Set[Tuple[str, str, str]] = set()

        # Extract IPs
        for ip in self._extract_ips(item):
            indicators.add((RULE_SHARED_IP, "ip_address", ip))

        # Extract Hashes
        for h in self._extract_hashes(item):
            indicators.add((RULE_SHARED_HASH, "file_hash", h))

        # Extract Processes
        for proc in self._extract_processes(item):
            indicators.add((RULE_SHARED_PROCESS, "process_name", proc))

        # Extract Accounts
        for acc in self._extract_accounts(item):
            indicators.add((RULE_SHARED_ACCOUNT, "user_account", acc))

        # Extract Threat Indicators
        for ind in self._extract_threat_indicators(item):
            indicators.add((RULE_SHARED_INDICATOR, "threat_indicator", ind))

        # Extract Forensic References
        for ref in self._extract_forensic_references(item):
            indicators.add((RULE_SHARED_FORENSIC_OBJECT, "forensic_reference", ref))

        return indicators

    def _extract_ips(self, item: Dict[str, Any]) -> Set[str]:
        ips = set()
        details = item.get("details") or {}
        meta = item.get("metadata_json") or {}

        candidates = [
            details.get("ip_address"),
            details.get("source_ip"),
            details.get("destination_ip"),
            details.get("foreign_addr"),
            meta.get("source_ip"),
            meta.get("foreign_addr"),
        ]

        # Scan text fields for IPv4 patterns
        for text in [item.get("title", ""), item.get("description", ""), str(item.get("evidence_reference", ""))]:
            if text:
                candidates.extend(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))

        for cand in candidates:
            if not cand:
                continue
            cand_str = str(cand).strip()
            try:
                ip_obj = ipaddress.IPv4Address(cand_str)
                # Eliminate loopback, unspecified (0.0.0.0), and broadcast (255.255.255.255)
                if not (ip_obj.is_loopback or ip_obj.is_unspecified or cand_str == "255.255.255.255"):
                    ips.add(cand_str)
            except (ipaddress.AddressValueError, ValueError):
                continue
        return ips

    def _extract_hashes(self, item: Dict[str, Any]) -> Set[str]:
        hashes = set()
        details = item.get("details") or {}
        meta = item.get("metadata_json") or {}

        candidates = [
            details.get("hash"),
            details.get("sha256"),
            details.get("md5"),
            details.get("sha1"),
            meta.get("rule_sha256"),
            meta.get("sha256"),
            meta.get("hash"),
        ]

        # Check explicit hash strings
        for text in [item.get("title", ""), item.get("description", ""), str(item.get("evidence_reference", ""))]:
            if text:
                # SHA-256 (64 hex), SHA-1 (40 hex), MD5 (32 hex)
                candidates.extend(re.findall(r"\b[a-fA-F0-9]{64}\b", text))
                candidates.extend(re.findall(r"\b[a-fA-F0-9]{40}\b", text))
                candidates.extend(re.findall(r"\b[a-fA-F0-9]{32}\b", text))

        for cand in candidates:
            if not cand:
                continue
            cand_str = str(cand).strip().lower()
            # Eliminate trivial hashes (all zeros, empty md5)
            if cand_str in {"d41d8cd98f00b204e9800998ecf8427e", "0" * 32, "0" * 40, "0" * 64}:
                continue
            if len(cand_str) in {32, 40, 64} and re.match(r"^[a-f0-9]+$", cand_str):
                hashes.add(cand_str)
        return hashes

    def _extract_processes(self, item: Dict[str, Any]) -> Set[str]:
        processes = set()
        details = item.get("details") or {}
        meta = item.get("metadata_json") or {}

        candidates = [
            details.get("process_name"),
            details.get("image_file_name"),
            details.get("file_name"),
            meta.get("process_name"),
            meta.get("image_file_name"),
            meta.get("owner"),
            item.get("path")
        ]

        # Scan text for executable binaries
        for text in [item.get("title", ""), item.get("description", "")]:
            if text:
                matches = re.findall(r"\b([a-zA-Z0-9_\-\.]+\.(?:exe|bat|ps1|vbs|sh|bin|dll))\b", text, re.IGNORECASE)
                candidates.extend(matches)

        for cand in candidates:
            if not cand:
                continue
            # Extract basename
            clean_name = str(cand).replace("\\", "/").split("/")[-1].strip().lower()
            if not clean_name or len(clean_name) < 4:
                continue
            if clean_name in BANNED_GENERIC_TERMS:
                continue
            # Must have executable extension or clean identifier
            if any(clean_name.endswith(ext) for ext in [".exe", ".bat", ".ps1", ".vbs", ".sh", ".bin", ".dll"]):
                processes.add(clean_name)
        return processes

    def _extract_accounts(self, item: Dict[str, Any]) -> Set[str]:
        accounts = set()
        details = item.get("details") or {}
        meta = item.get("metadata_json") or {}

        candidates = [
            details.get("user"),
            details.get("target_user"),
            details.get("username"),
            details.get("account"),
            meta.get("user"),
            meta.get("target_user"),
            meta.get("subject_user"),
        ]

        for cand in candidates:
            if not cand:
                continue
            # Strip domain prefix (e.g. CORP\user)
            clean_acc = str(cand).replace("\\", "/").split("/")[-1].strip().lower()
            if len(clean_acc) < 3:
                continue
            if clean_acc in BANNED_GENERIC_TERMS:
                continue
            if clean_acc.isdigit():
                continue
            accounts.add(clean_acc)
        return accounts

    def _extract_threat_indicators(self, item: Dict[str, Any]) -> Set[str]:
        indicators = set()
        details = item.get("details") or {}
        meta = item.get("metadata_json") or {}
        ref = str(item.get("evidence_reference") or item.get("source_reference") or "")

        candidates = [
            details.get("rule_name"),
            details.get("rule_id"),
            meta.get("rule_name"),
        ]

        if ref.startswith("rule:"):
            candidates.append(ref.split("rule:", 1)[1])

        for cand in candidates:
            if not cand:
                continue
            clean_ind = str(cand).strip()
            if len(clean_ind) < 3 or clean_ind.lower() in BANNED_GENERIC_TERMS:
                continue
            # Ignore generic rule bundle filename
            if clean_ind.lower() in {"adfir_test_rules", "default", "custom_rules"}:
                continue
            indicators.add(clean_ind)
        return indicators

    def _extract_forensic_references(self, item: Dict[str, Any]) -> Set[str]:
        """
        Extracts locally scoped forensic pointers (inode, PID, EVTX record).
        Crucial Forensic Invariant: Identifiers that are only locally meaningful MUST NOT
        be treated as globally unique across different evidence or without evidence context.
        If contextual provenance is absent, no correlation is created.
        """
        refs = set()
        ev_id = item.get("evidence_id")
        if not ev_id:
            return refs

        details = item.get("details") or {}
        meta = item.get("metadata_json") or {}

        for ref_field in [item.get("evidence_reference"), item.get("source_reference")]:
            if not ref_field:
                continue
            ref_str = str(ref_field).strip().lower()

            # Contextually scoped inode
            m_inode = re.match(r"^inode:(\d+)$", ref_str)
            if m_inode:
                refs.add(f"inode:{m_inode.group(1)} [ev:{ev_id}]")
                continue

            # Contextually scoped PID
            m_pid = re.match(r"^pid:(\d+)$", ref_str)
            if m_pid:
                refs.add(f"pid:{m_pid.group(1)} [ev:{ev_id}]")
                continue

            # Contextually scoped EVTX record
            m_rec = re.match(r"^record:(\d+):eid:(\d+)$", ref_str)
            if m_rec:
                log_src = item.get("path") or details.get("channel") or details.get("source") or meta.get("channel") or ""
                clean_src = str(log_src).replace("\\", "/").split("/")[-1].lower() if log_src else "evtx"
                refs.add(f"record:{m_rec.group(1)}:eid:{m_rec.group(2)} [ev:{ev_id}:{clean_src}]")
                continue

        return refs

    def _is_process_corroborated(self, items: List[Dict[str, Any]], proc_name: str) -> bool:
        """
        Ensures SHARED_PROCESS requires meaningful forensic corroboration:
        - same executable plus compatible file path
        - same executable plus supporting cryptographic hash
        - same executable plus matching command line arguments
        - same executable with cross-domain corroboration (storage staging vs execution/memory with threat context)
        Merely sharing a common executable name across unrelated records does NOT create a correlation.
        """
        if len(items) < 2:
            return False

        paths = []
        hashes = []
        cmdlines = []
        domains = []
        has_threat_context = False

        storage_tools = {"diskagent", "sleuthkit", "fls", "malwareagent", "yara", "clamav"}
        execution_tools = {"memoryagent", "volatility3", "pslist", "netscan", "logagent", "python-evtx", "evtx"}

        for it in items:
            details = it.get("details") or {}
            meta = it.get("metadata_json") or {}
            tool_name = str(it.get("tool") or it.get("source_tool") or it.get("agent") or "").lower()

            # Path collection
            item_path = it.get("path") or details.get("path") or details.get("file_path") or details.get("image_path") or meta.get("path")
            if item_path:
                norm_p = str(item_path).replace("\\", "/").strip().lower()
                if norm_p.endswith(proc_name.lower()) or proc_name.lower() in norm_p.split("/")[-1]:
                    paths.append(norm_p)

            # Hash collection
            h = details.get("sha256") or details.get("hash") or details.get("md5") or meta.get("sha256") or meta.get("hash") or meta.get("md5")
            if h:
                h_str = str(h).strip().lower()
                if len(h_str) in {32, 40, 64} and h_str not in {"0" * 32, "0" * 40, "0" * 64}:
                    hashes.append(h_str)

            # Cmdline collection
            cmd = details.get("command_line") or details.get("cmdline") or meta.get("command_line")
            if cmd:
                cmd_str = str(cmd).strip().lower()
                if len(cmd_str) >= 5:
                    cmdlines.append(cmd_str)

            # Domain identification
            if any(st in tool_name for st in storage_tools) or it.get("path"):
                domains.append("storage")
            if any(et in tool_name for et in execution_tools) or details.get("pid") or details.get("process_name"):
                domains.append("execution")

            # Threat / suspicion context check
            text_corpus = f"{it.get('title', '')} {it.get('description', '')} {it.get('category', '')} {it.get('finding_type', '')}".lower()
            threat_words = [
                "suspicious", "staged", "dump", "beacon", "mimikatz", "backdoor",
                "malware", "c2", "trojan", "exploit", "unallocated", "privilege", "implant"
            ]
            if any(tw in text_corpus for tw in threat_words) or it.get("mitre_techniques"):
                has_threat_context = True

        # 1. Corroboration via matching full file path across at least 2 items
        if len(paths) >= 2:
            path_counts = {}
            for p in paths:
                path_counts[p] = path_counts.get(p, 0) + 1
                if path_counts[p] >= 2 and ("/" in p or "\\" in p):
                    return True

        # 2. Corroboration via matching cryptographic hash across at least 2 items
        if len(hashes) >= 2:
            hash_counts = {}
            for h in hashes:
                hash_counts[h] = hash_counts.get(h, 0) + 1
                if hash_counts[h] >= 2:
                    return True

        # 3. Corroboration via matching command line across at least 2 items
        if len(cmdlines) >= 2:
            cmd_counts = {}
            for c in cmdlines:
                cmd_counts[c] = cmd_counts.get(c, 0) + 1
                if cmd_counts[c] >= 2:
                    return True

        # 4. Cross-domain forensic link (Storage + Execution) with threat / suspicious context
        if "storage" in domains and "execution" in domains and has_threat_context:
            return True

        return False

    def _calculate_confidence(self, rule: str, finding_count: int, tool_count: int) -> float:
        """
        Calculates deterministic confidence without randomness or artificial inference.
        """
        base_confidence = {
            RULE_SHARED_HASH: 0.98,
            RULE_SHARED_IP: 0.95,
            RULE_SHARED_INDICATOR: 0.95,
            RULE_SHARED_FORENSIC_OBJECT: 0.95,
            RULE_SHARED_PROCESS: 0.90,
            RULE_SHARED_ACCOUNT: 0.85
        }.get(rule, 0.80)

        # Multi-tool corroborated boost (deterministic)
        tool_boost = 0.05 if tool_count > 1 else 0.0
        finding_boost = min(0.05, 0.02 * max(0, finding_count - 1))
        return min(1.0, round(base_confidence + tool_boost + finding_boost, 2))

    def _generate_explanation(
        self, rule: str, entity: str, finding_count: int, artifact_count: int, tools: List[str]
    ) -> Tuple[str, str]:
        """
        Generates deterministic human-readable titles and explanations.
        """
        tools_str = ", ".join(tools) if tools else "Specialist Tools"

        if rule == RULE_SHARED_IP:
            title = f"Shared Network IP Link: {entity}"
            desc = f"Network indicator '{entity}' is corroborated across {finding_count} finding(s) from tool(s): {tools_str}."
        elif rule == RULE_SHARED_PROCESS:
            title = f"Corroborated Process Binary: {entity}"
            desc = f"Process executable '{entity}' is corroborated across {finding_count} finding(s) and {artifact_count} artifact(s) from tool(s): {tools_str} with compatible forensic context."
        elif rule == RULE_SHARED_ACCOUNT:
            title = f"Shared User Account Activity: {entity}"
            desc = f"Security principal account '{entity}' was identified across {finding_count} event(s) from tool(s): {tools_str}."
        elif rule == RULE_SHARED_HASH:
            title = f"Shared Cryptographic Hash: {entity[:16]}..."
            desc = f"File hash '{entity}' was observed in multiple forensic contexts from tool(s): {tools_str}."
        elif rule == RULE_SHARED_INDICATOR:
            title = f"Correlated Threat Signature: {entity}"
            desc = f"Malware/threat signature '{entity}' links multiple forensic indicators from tool(s): {tools_str}."
        elif rule == RULE_SHARED_FORENSIC_OBJECT:
            title = f"Contextual Forensic Object: {entity}"
            desc = f"Forensic reference '{entity}' links {finding_count} findings across tool(s): {tools_str} within verified evidence context."
        else:
            title = f"Correlated Artifact Chain: {entity}"
            desc = f"Entity '{entity}' links findings across tool(s): {tools_str}."

        return title, desc
