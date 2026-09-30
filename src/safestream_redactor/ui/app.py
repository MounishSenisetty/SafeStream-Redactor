"""SafeStream web playground (Streamlit).

Start it with ``safestream ui``, which applies the local-only Streamlit settings
(see :mod:`safestream_redactor.ui.launcher`). All logic lives in
:mod:`safestream_redactor.ui.core`; this module only lays out widgets.
"""

from __future__ import annotations

import importlib.util
import os
import secrets
from pathlib import Path
from typing import Any

import streamlit as st

from safestream_redactor import __version__, netguard
from safestream_redactor.engine import DEFAULT_CHUNK_SIZE, DEFAULT_OVERLAP
from safestream_redactor.ui.core import (
    DOWNLOAD_LIMIT_BYTES,
    MAX_INPUT_BYTES,
    PATTERN_TYPES,
    PREVIEW_CHARS,
    SAMPLE_TEXT,
    SEVERITY_COLORS,
    UPLOAD_TYPES,
    Finding,
    InputError,
    RedactStyle,
    Settings,
    SettingsError,
    build_redactor,
    check_text_size,
    counts_severity,
    decode_upload,
    default_workers,
    discard_workdir,
    download_name,
    estimate_seconds,
    finding_rows,
    highlight_html,
    new_workdir,
    parse_rules,
    privacy_status,
    read_head,
    redact_large,
    redact_text,
    save_destination,
    save_output,
    scan,
    spool_upload,
    summarize,
    worst_severity,
)

_STYLES = """
<style>
.ss-view { white-space: pre-wrap; word-break: break-word; margin: 0;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.85rem;
  line-height: 1.55; padding: 0.75rem 1rem; max-height: 26rem; overflow: auto;
  border: 1px solid rgba(128, 128, 128, 0.35); border-radius: 0.5rem; }
.ss-view mark { color: inherit; border-radius: 0.2rem; padding: 0 0.1rem; }
.ss-legend span { display: inline-block; margin-right: 0.9rem; font-size: 0.8rem; }
.ss-legend i { display: inline-block; width: 0.8rem; height: 0.8rem;
  border-radius: 0.2rem; margin-right: 0.3rem; vertical-align: -0.1rem; }
</style>
"""
_STYLE_LABELS = {
    RedactStyle.REPLACE: "Replace",
    RedactStyle.MASK: "Mask",
    RedactStyle.HASH: "Hash",
}
_MIB = 1024 * 1024


def _load_sample() -> None:
    st.session_state["text"] = SAMPLE_TEXT


def _sidebar() -> tuple[str, Settings]:
    with st.sidebar:
        st.header("Settings")
        mode = st.radio(
            "Mode",
            ["Detect", "Redact"],
            key="mode",
            horizontal=True,
            help="Detect highlights findings; Redact shows the sanitized output.",
        )
        style, replacement, keep_last, hash_key = RedactStyle.REPLACE, "[REDACTED]", 4, ""
        if mode == "Redact":
            style = st.radio(
                "Redaction style",
                list(RedactStyle),
                format_func=_STYLE_LABELS.__getitem__,
                key="style",
                horizontal=True,
            )
            if style is RedactStyle.REPLACE:
                replacement = st.text_input("Replacement", "[REDACTED]", key="replacement")
            elif style is RedactStyle.MASK:
                keep_last = int(
                    st.number_input(
                        "Characters left visible",
                        min_value=0,
                        max_value=16,
                        value=4,
                        key="keep_last",
                        help="Never more than half of a value, so short values stay hidden.",
                    )
                )
            else:
                st.session_state.setdefault("hash_key", secrets.token_hex(16))
                hash_key = st.text_input(
                    "HMAC key",
                    key="hash_key",
                    type="password",
                    help="Random for this session. Set your own to get the same pseudonyms "
                    "across runs; anyone with the key can reverse low-entropy values.",
                )

        st.subheader("Detection")
        min_confidence = st.slider("Minimum confidence", 0.0, 1.0, 0.5, 0.05, key="min_confidence")
        with st.expander("Entity types"):
            chosen = st.multiselect(
                "Pattern types", PATTERN_TYPES, default=list(PATTERN_TYPES), key="types"
            )
        if not chosen:
            st.caption("No pattern types selected: only custom rules and name tiers run.")
        use_entropy = st.toggle(
            "High-entropy secrets",
            value=True,
            key="use_entropy",
            help="Keys and tokens with no published format, found by entropy.",
        )
        use_names = st.toggle(
            "Name heuristics",
            key="use_names",
            help="Dependency-free PERSON/ORG detection from honorifics, cues, and gazetteers.",
        )
        ner_installed = importlib.util.find_spec("spacy") is not None
        use_ner = st.toggle(
            "spaCy NER",
            key="use_ner",
            disabled=not ner_installed,
            help="PERSON/ORG/LOC from a spaCy model"
            + ("" if ner_installed else " (install the [ner] extra to enable)."),
        )

        st.subheader("Custom rules")
        words = st.text_area(
            "Words or phrases, one per line", key="custom_words", height=90, placeholder="ProjectX"
        )
        patterns = st.text_area(
            "Regex patterns, one per line",
            key="custom_patterns",
            height=90,
            placeholder=r"\bEMP-\d{6}\b",
        )

        with st.expander("Streaming"):
            chunk_size = st.number_input(
                "Chunk size (characters)",
                min_value=1,
                value=DEFAULT_CHUNK_SIZE,
                step=1024,
                key="chunk_size",
            )
            overlap = st.number_input(
                "Overlap (characters)",
                min_value=0,
                value=DEFAULT_OVERLAP,
                step=1024,
                key="overlap",
                help="Carried between chunks so an entity split by a boundary is still "
                "found. Below the detectors' safe minimum the engine refuses to run.",
            )

    settings = Settings(
        min_confidence=float(min_confidence),
        chunk_size=int(chunk_size),
        overlap=int(overlap),
        types=None if len(chosen) == len(PATTERN_TYPES) else tuple(chosen),
        use_entropy=use_entropy,
        use_names=use_names,
        use_ner=use_ner,
        custom_words=parse_rules(words),
        custom_patterns=parse_rules(patterns),
        style=style,
        replacement=replacement,
        keep_last=keep_last,
        hash_key=hash_key,
    )
    return str(mode), settings


def _privacy_banner() -> None:
    status = privacy_status(
        st.get_option("server.address"),
        bool(st.get_option("browser.gatherUsageStats")),
        netguard.is_installed(),
    )
    if status.local_only:
        st.success(
            "**Local-only processing.** Text and files are processed on this machine: in "
            "memory, or for large uploads in a private temporary folder that is deleted when "
            "the server stops. The page is served on loopback only, Streamlit telemetry is "
            "off, and the offline guard blocks outbound network connections.",
            icon="🔒",
        )
    else:
        st.warning(
            "**This page is not fully local.**\n\n"
            + "\n".join(f"- {issue}" for issue in status.issues),
            icon="⚠️",
        )


def _read_input() -> tuple[str, str | None, Any]:
    """The text to analyse in the page, the upload's name, and a large upload.

    An upload bigger than :data:`MAX_INPUT_BYTES` is returned as the third item
    (with empty text) for the large-file path instead of being decoded here.
    """
    paste_tab, upload_tab = st.tabs(["Paste text", "Upload file"])
    with paste_tab:
        st.button("Load sample log", on_click=_load_sample)
        pasted = st.text_area(
            "Text or log lines",
            key="text",
            height=200,
            placeholder="Paste logs, config, or any text…",
        )
    with upload_tab:
        limit_mb = int(st.get_option("server.maxUploadSize"))
        upload = st.file_uploader(
            f"A text file up to {_size_label(limit_mb * _MIB)}",
            type=list(UPLOAD_TYPES),
            key="upload",
            help=f"Files up to {MAX_INPUT_BYTES // _MIB} MiB are analysed in the page. Larger "
            "files are redacted by the streaming engine and previewed. Streamlit keeps an "
            "upload in memory while it is selected.",
        )
    if upload is not None:
        if upload.size > MAX_INPUT_BYTES:
            return "", upload.name, upload
        decoded = decode_upload(upload.getvalue(), MAX_INPUT_BYTES)
        st.caption(f"Scanning **{upload.name}**. Remove it to scan pasted text instead.")
        if decoded.replaced_bytes:
            st.warning(
                f"{decoded.replaced_bytes} byte(s) were not valid UTF-8 and could not be "
                "scanned. Convert the file to UTF-8 for full coverage."
            )
        return decoded.text, upload.name, None
    check_text_size(pasted, MAX_INPUT_BYTES)
    return pasted, None, None


def _legend() -> None:
    items = "".join(
        f'<span><i style="background:{color}"></i>{level}</span>'
        for level, color in SEVERITY_COLORS.items()
    )
    st.html(f'{_STYLES}<div class="ss-legend">{items}</div>')


def _view(text: str, findings: list[Finding], *, redacted: bool = False) -> None:
    st.html(_STYLES + highlight_html(text, findings, redacted=redacted))


def _findings_table(findings: list[Finding], title: str = "Findings") -> None:
    with st.expander(f"{title} ({len(findings)})", expanded=True):
        if not findings:
            st.write("Nothing detected with the current settings.")
            return
        reveal = st.toggle(
            "Reveal matched values",
            key="reveal",
            help="Hidden by default, like `safestream detect`, so the table is safe to share.",
        )
        st.dataframe(finding_rows(findings, reveal=reveal), hide_index=True)


def _metrics(text: str, findings: list[Finding]) -> None:
    counts = summarize(findings)
    a, b, c, d = st.columns(4)
    a.metric("Findings", len(findings))
    b.metric("Entity types", len(counts))
    c.metric("Highest severity", worst_severity(findings) or "none")
    d.metric("Characters", f"{len(text):,}")
    if counts:
        st.caption(" · ".join(f"{name}: {n}" for name, n in counts.items()))


def _size_label(n_bytes: float) -> str:
    return f"{n_bytes / 1024**3:.1f} GiB" if n_bytes >= 1024**3 else f"{n_bytes / _MIB:,.1f} MiB"


def _duration(seconds: float) -> str:
    if seconds < 90:
        return f"{max(1, round(seconds))} s"
    return f"{seconds / 60:.0f} min"


def _default_save_dir() -> str:
    # `safestream ui` passes the directory it was started from
    configured = os.environ.get("SAFESTREAM_UI_OUTPUT_DIR")
    if configured:
        return configured
    downloads = Path.home() / "Downloads"
    return str(downloads if downloads.is_dir() else Path.cwd())


def _forget_large_file() -> None:
    state = st.session_state.pop("large", None)
    if state:
        discard_workdir(state["workdir"])


def _process_large(upload: Any, settings: Settings, redactor: Any) -> dict[str, Any] | None:
    """Spool and redact a large upload once per (file, settings); cached in the session."""
    key = (upload.file_id, settings)
    state: dict[str, Any] | None = st.session_state.get("large")
    if state is not None and state["key"] == key:
        return state
    workers = default_workers()
    eta = _duration(estimate_seconds(upload.size, workers))
    # a large run takes minutes: start it on request, never on an incidental rerun
    if not st.button(f"Process {upload.name}", type="primary", key="process_large"):
        st.caption(f"Takes about {eta} on this machine ({workers} worker(s)).")
        return None
    _forget_large_file()
    workdir = new_workdir()
    source, output = os.path.join(workdir, "input"), os.path.join(workdir, "output")
    try:
        with st.status(f"Processing {upload.name}…", expanded=True) as status:
            st.write("Copying the upload to a private temporary folder…")
            upload.seek(0)
            spool_upload(upload, source)
            head = read_head(source)
            st.write(f"Redacting with {workers} worker(s), about {eta}…")
            result = redact_large(redactor, source, output, workers=workers)
            os.remove(source)
            status.update(
                label=f"Processed {upload.name} in {_duration(result.seconds)}",
                state="complete",
                expanded=False,
            )
    except BaseException:
        discard_workdir(workdir)
        raise
    state = {"key": key, "result": result, "head": head, "workdir": workdir, "saved": None}
    st.session_state["large"] = state
    return state


def _large_file(upload: Any, mode: str, settings: Settings, redactor: Any) -> None:
    st.info(
        f"**{upload.name}** is {_size_label(upload.size)}, more than the "
        f"{MAX_INPUT_BYTES // _MIB} MiB analysed in the page. It is redacted by the "
        "streaming engine on every core (constant memory, output identical to the CLI). "
        f"Counts cover the whole file; highlights cover its first {PREVIEW_CHARS:,} "
        "characters.",
        icon="📦",
    )
    try:
        state = _process_large(upload, settings, redactor)
    except InputError as exc:
        st.error(str(exc), icon="🚫")
        return
    if state is None:
        return
    result, head = state["result"], state["head"]
    counts = dict(sorted(result.stats.counts.items(), key=lambda kv: (-kv[1], kv[0])))
    a, b, c, d = st.columns(4)
    a.metric("Findings", f"{result.stats.total:,}")
    b.metric("Entity types", len(counts))
    c.metric("Highest severity", counts_severity(counts) or "none")
    d.metric("Size", _size_label(result.input_bytes))
    if counts:
        st.caption(" · ".join(f"{name}: {n:,}" for name, n in counts.items()))
    rate = result.input_bytes / _MIB / max(result.seconds, 1e-9)
    st.caption(
        f"Processed in {_duration(result.seconds)} ({rate:.1f} MiB/s on "
        f"{result.workers} worker(s))."
    )
    if result.stats.decode_replacements:
        st.warning(
            f"{result.stats.decode_replacements:,} byte(s) were not valid UTF-8 and could "
            "not be scanned. Convert the file to UTF-8 for full coverage."
        )

    head_findings = scan(redactor, head)
    if mode == "Detect":
        st.subheader("Annotated preview")
        _legend()
        _view(head, head_findings)
        _findings_table(head_findings, title="Findings in the preview")
        return
    left, right = st.columns(2)
    with left:
        st.subheader("Original (preview)")
        _view(head, head_findings)
    with right:
        st.subheader("Redacted (preview)")
        _view(head, head_findings, redacted=True)
    _large_output(upload.name, state)
    _findings_table(head_findings, title="Findings in the preview")


def _large_output(name: str, state: dict[str, Any]) -> None:
    st.subheader("Redacted file")
    if state["saved"]:
        st.success(f"Saved to `{state['saved']}`", icon="✅")
        return
    result = state["result"]
    output = Path(result.output_path)
    if result.output_bytes <= DOWNLOAD_LIMIT_BYTES:
        st.download_button(
            f"Download ({_size_label(result.output_bytes)})",
            output.read_bytes,  # read only when clicked, never on a rerun
            file_name=download_name(name),
            mime="text/plain",
            on_click="ignore",
            type="primary",
        )
    local = privacy_status(
        st.get_option("server.address"), False, netguard.is_installed()
    ).local_only
    if not local:
        # writing to this machine's disk is for its own user only
        st.caption("Saving to a folder is available only when the page is served on loopback.")
        return
    if result.output_bytes > DOWNLOAD_LIMIT_BYTES:
        st.caption(
            f"The output is {_size_label(result.output_bytes)}, too large for a browser "
            "download from this page. Save it to a folder on this machine instead."
        )
    folder = st.text_input("Save to folder", value=_default_save_dir(), key="save_dir")
    if st.button("Save redacted file", key="save_large"):
        try:
            destination = save_output(result, save_destination(folder, name))
        except InputError as exc:
            st.error(str(exc), icon="🚫")
            return
        state["saved"] = str(destination)
        discard_workdir(state["workdir"])  # the output moved out; nothing left in it
        st.rerun()


def main() -> None:
    st.set_page_config(page_title="SafeStream Redactor", page_icon="🛡️", layout="wide")
    # Any outbound connection from this process now fails closed (idempotent).
    netguard.install()
    mode, settings = _sidebar()

    st.title("SafeStream Redactor")
    st.caption(f"v{__version__} · detect and redact secrets and PII, locally")
    _privacy_banner()

    try:
        text, name, large = _read_input()
    except InputError as exc:
        st.error(str(exc), icon="🚫")
        return
    if large is None:
        _forget_large_file()  # its upload was removed: drop the scratch output
    else:
        try:
            redactor = build_redactor(settings)
        except SettingsError as exc:
            st.error(f"**Invalid settings.** {exc}", icon="⚠️")
            return
        _large_file(large, mode, settings, redactor)
        return
    if not text:
        st.info("Paste text or upload a file to begin, or load the sample log.")
        return
    try:
        redactor = build_redactor(settings)
    except SettingsError as exc:
        st.error(f"**Invalid settings.** {exc}", icon="⚠️")
        return

    findings = scan(redactor, text)
    _metrics(text, findings)
    if len(text) > PREVIEW_CHARS:
        st.caption(
            f"The views below show the first {PREVIEW_CHARS:,} characters. Findings, "
            "counts, and the redacted output cover the whole input."
        )

    if mode == "Detect":
        st.subheader("Annotated input")
        _legend()
        _view(text, findings)
        _findings_table(findings)
        return

    redacted = redact_text(text, findings)
    left, right = st.columns(2)
    with left:
        st.subheader("Original")
        _view(text, findings)
    with right:
        st.subheader("Redacted")
        _view(text, findings, redacted=True)
    st.subheader("Redacted output")
    st.caption("Copy it with the icon on the block, or download it as a file.")
    tall = redacted.count("\n") > 15
    st.code(redacted, language=None, wrap_lines=True, height=320 if tall else "content")
    st.download_button(
        "Download redacted file",
        redacted.encode("utf-8"),
        file_name=download_name(name),
        mime="text/plain",
        on_click="ignore",
        type="primary",
    )
    _findings_table(findings)


if __name__ == "__main__":
    main()
