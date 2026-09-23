import json
import logging
import os
import socket
import traceback
from collections import OrderedDict
from contextlib import contextmanager
from logging import getLogger
from urllib.parse import quote

import requests
import streamlit as st
import yaml
from cryptography.hazmat.primitives import serialization
from sqlalchemy import create_engine, text
from sqlalchemy.dialects import registry
from sqlalchemy.exc import DatabaseError, InterfaceError

from core.keys import generate_keys
from core.snowflake import extract_snowflake_account, is_valid_snowflake_account
from datetime import datetime, timezone

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
APP_START_TIME = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
# Container ID: in Docker HOSTNAME is the container ID, locally use machine hostname
CONTAINER_ID = os.environ.get("HOSTNAME", socket.gethostname())


def _generate_container_info_file():
    """Generate static/container-info.json for deployment verification.

    This file is served by Streamlit's static file serving and used by the
    deployment script to verify which container is serving traffic.
    Works both locally and in Docker.
    """
    static_dir = os.path.join(CURRENT_DIR, "static")
    os.makedirs(static_dir, exist_ok=True)

    info = {
        "container_id": CONTAINER_ID,
        "git_commit": os.environ.get("GIT_COMMIT", "local"),
        "started_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    info_path = os.path.join(static_dir, "container-info.json")
    with open(info_path, "w") as f:
        json.dump(info, f, indent=2)

    print(f"Container info written to {info_path}: {info}")


# Generate container info file at module load (once per process)
_generate_container_info_file()
sql_sections = {
    "snowflake_setup": "Setting up the dbt User and Roles",
    "snowflake_import": "Importing Raw Tables",
    "capstone_airstats": "Importing AIRSTATS Capstone Tables",
}

# SQL resource files configuration
# Each entry: (filename, required_for_modes) where modes is a list or None for always required
SQL_RESOURCE_FILES = [
    ("course-resources.md", None),  # Always required
    ("capstone-resources.md", None),  # Always required (capstone is now part of standard course)
]


def check_sql_resource_files(course_mode: str) -> list[str]:
    """Check if all required SQL resource files exist.

    Returns a list of warning messages for missing files.
    """
    warnings = []
    for filename, required_modes in SQL_RESOURCE_FILES:
        filepath = os.path.join(CURRENT_DIR, filename)
        is_required = required_modes is None or course_mode in required_modes

        if is_required and not os.path.exists(filepath):
            mode_desc = f" (required for {course_mode} mode)" if required_modes else ""
            warnings.append(
                f"SQL resource file '{filename}' not found{mode_desc}. "
                f"Some features may not work correctly."
            )
            logging.error(f"Missing SQL resource file: {filepath}")

    return warnings


def generate_profiles_yml(snowflake_account: str, private_key_pem_text: str) -> str:
    """Generate profiles.yml content from template with account and private key."""
    template_path = os.path.join(CURRENT_DIR, "profiles.template.yml")

    with open(template_path, "r") as f:
        template_content = f.read()

    # Replace placeholders
    profiles_content = template_content.replace(
        "{{snowflake_account}}", snowflake_account
    ).replace("{{private_key_pem_text}}", private_key_pem_text)

    return profiles_content


def parse_profiles_yml(profiles_content: str) -> tuple[str, str]:
    """Parse profiles.yml and extract snowflake_account and private_key_pem_text.

    Returns (snowflake_account, private_key_pem_text) with escaped \\n in the key.
    Raises ValueError if parsing fails.
    """
    try:
        parsed = yaml.safe_load(profiles_content)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML format: {e}")

    try:
        dev_config = parsed["airbnb"]["outputs"]["dev"]
    except (KeyError, TypeError):
        raise ValueError("Invalid profiles.yml structure. Expected airbnb.outputs.dev hierarchy.")

    account = dev_config.get("account")
    if not account:
        raise ValueError("Missing 'account' field in profiles.yml")

    private_key = dev_config.get("private_key")
    if not private_key:
        raise ValueError("Missing 'private_key' field in profiles.yml")

    # YAML parses escaped \n in double-quoted strings into actual newlines.
    # Convert back to escaped \n for preset-instructions.md format.
    private_key_pem_text = private_key.replace("\n", "\\n")

    return account, private_key_pem_text


def parse_profiles_yml_full(profiles_content: str) -> dict:
    """Parse profiles.yml and return all fields needed for env scripts.

    Unlike parse_profiles_yml(), this preserves real newlines in private_key
    because shell scripts (bash, PowerShell) need a real PEM block, not a
    literal-\\n single line.

    Returns dict with keys: account, user, private_key, private_key_passphrase.
    Defaults user to "dbt" and passphrase to "q" to match profiles.template.yml.
    Raises ValueError on invalid input.
    """
    try:
        parsed = yaml.safe_load(profiles_content)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML format: {e}")

    try:
        dev_config = parsed["airbnb"]["outputs"]["dev"]
    except (KeyError, TypeError):
        raise ValueError(
            "Invalid profiles.yml structure. Expected airbnb.outputs.dev hierarchy."
        )

    account = dev_config.get("account")
    if not account:
        raise ValueError("Missing 'account' field in profiles.yml")

    private_key = dev_config.get("private_key")
    if not private_key:
        raise ValueError("Missing 'private_key' field in profiles.yml")

    return {
        "account": account,
        "user": dev_config.get("user") or "dbt",
        "private_key": private_key,
        "private_key_passphrase": dev_config.get("private_key_passphrase") or "q",
    }


def generate_set_env_sh(values: dict) -> str:
    """Generate a bash/zsh script that exports Snowflake env vars.

    Students dot-source it: `source set-env.sh`. The PEM goes inside a plain
    double-quoted string — bash preserves embedded newlines.
    """
    pem = values["private_key"]
    if not pem.endswith("\n"):
        pem += "\n"

    return (
        "#!/usr/bin/env bash\n"
        "# Source this file before running dbt:\n"
        "#   . set-env.sh\n"
        "#   or . ../set-env.sh if you run it from the airbnb/ folder.\n"
        "# !! Do this every time you open a new terminal, as env vars are not persisted !!\n"
        "\n"
        f'export SNOWFLAKE_ACCOUNT="{values["account"]}"\n'
        f'export DBT_USER="{values["user"]}"\n'
        f'export PRIVATE_KEY_PASSPHRASE="{values["private_key_passphrase"]}"\n'
        f'export PRIVATE_KEY="{pem}"\n'
    )


def generate_set_env_ps1(values: dict) -> str:
    """Generate a PowerShell script that sets Snowflake env vars.

    Students dot-source it: `. .\\set-env.ps1`. The PEM goes inside a
    here-string (@"..."@); the closing token must sit at column 0.
    """

    def esc(value: str) -> str:
        return value.replace("`", "``").replace('"', '`"')

    pem = values["private_key"]
    if not pem.endswith("\n"):
        pem += "\n"

    return (
        "# Dot-source this file before running dbt:\n"
        "#   . .\\set-env.ps1\n"
        "# or . ..\\set-env.ps1 if you're running the script from airbnb/ folder\n"
        "# !! Do this every time you open a new PowerShell terminal, as env vars are not persisted !!\n"
        "# First-time only (one-shot per machine):\n"
        "#   Set-ExecutionPolicy -Scope CurrentUser RemoteSigned\n"
        "\n"
        f'$env:SNOWFLAKE_ACCOUNT = "{esc(values["account"])}"\n'
        f'$env:DBT_USER = "{esc(values["user"])}"\n'
        f'$env:PRIVATE_KEY_PASSPHRASE = "{esc(values["private_key_passphrase"])}"\n'
        f'$env:PRIVATE_KEY = @"\n'
        f"{pem}"
        '"@\n'
    )


def generate_preset_instructions(
    snowflake_account: str, private_key_pem_text: str
) -> str:
    """Generate preset-instructions.md content with SQLAlchemy URL and Security JSON."""
    # Convert PEM to single line with visible \n

    content = f"""# Preset Instructions

## SQLAlchemy URL
```
snowflake://preset@{snowflake_account}/AIRBNB?role=REPORTER&warehouse=COMPUTE_WH
```

## Security JSON
```json
{{
    "auth_method": "keypair",
    "auth_params": {{
        "privatekey_body": "{private_key_pem_text}",
        "privatekey_pass": "q"
    }}
}}
```

## Instructions
1. Use the SQLAlchemy URL above to connect to your Snowflake database
2. Use the Security JSON configuration for authentication
3. The private key is already formatted with escaped newlines for direct use
""".replace(
        f"{snowflake_account}", snowflake_account
    )

    return content


@contextmanager
def get_snowflake_connection(account, username, password, passcode=None):
    # URL encode the credentials to handle special characters. Use quote() with
    # safe="" (not quote_plus): quote_plus encodes spaces as "+", which SQLAlchemy's
    # URL parser does NOT decode back to a space in the user:pass@host portion, so a
    # password with a space would reach Snowflake as a literal "+". quote(safe="")
    # percent-encodes everything (e.g. space -> %20), which round-trips correctly.
    encoded_username = quote(username, safe="")
    encoded_password = quote(password, safe="")
    encoded_account = quote(account, safe="")

    # Never log this: it carries the student's admin password.
    connection_string = f"snowflake://{encoded_username}:{encoded_password}@{encoded_account}/AIRBNB/DEV?warehouse=COMPUTE_WH&role=ACCOUNTADMIN&account_identifier={encoded_account}"

    # Add passcode to connect_args if provided (for TOTP-based MFA)
    connect_args = {}
    if passcode:
        connect_args["passcode"] = passcode

    engine = create_engine(connection_string, connect_args=connect_args)
    connection = engine.connect()

    try:
        yield connection
    finally:
        connection.close()
        engine.dispose()


@contextmanager
def get_dbt_connection(account, login_name, role, private_key_pem):
    """Connect to Snowflake using dbt user with private key authentication."""

    # URL encode the login name and account to handle special characters. Use
    # quote(safe="") rather than quote_plus so spaces become %20 (which round-trips)
    # instead of "+" (which SQLAlchemy leaves literal in the user@host portion).
    encoded_login_name = quote(login_name, safe="")
    encoded_account = quote(account, safe="")

    # Load the private key from PEM format
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=b"q",  # The passphrase used to encrypt the key
        backend=None,
    )

    # Convert to DER format (unencrypted) as bytes for connect_args
    private_key_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Create connection string for dbt user (without private_key in URL)
    connection_string = (
        f"snowflake://{encoded_login_name}@{encoded_account}/AIRBNB?"
        f"role={role}&warehouse=COMPUTE_WH&"
        f"account_identifier={encoded_account}"
    )

    print(f"DBT Connection string: {connection_string}")

    # Pass private key via connect_args as required by Snowflake SQLAlchemy
    engine = create_engine(
        connection_string,
        connect_args={
            "private_key": private_key_der,
        },
    )
    connection = engine.connect()

    try:
        yield connection
    finally:
        connection.close()
        engine.dispose()


def streamlit_session_id():
    try:
        from streamlit.runtime import get_instance
        from streamlit.runtime.scriptrunner import get_script_run_ctx

        runtime = get_instance()
        ctx = get_script_run_ctx()
        if ctx is None:
            return "nosession"
        session_id = ctx.session_id
        session_info = runtime._session_mgr.get_session_info(session_id)
        if session_info is None:
            return "nosession"
        return session_info.session.id
    except (AttributeError, TypeError):
        # Running in test environment (AppTest) where runtime is mocked
        return "test-session"


def get_sql_commands(md, public_key=None):
    commands = OrderedDict()
    current_section = None
    in_named_sql = False
    for line in md.split("\n"):
        if in_named_sql:
            if line.startswith("```"):
                in_named_sql = False
            else:
                if line.strip() == "" or line.startswith("--"):
                    continue
                # add command to current section
                if current_section not in commands:
                    commands[current_section] = ""

                # Replace public key placeholder if present and public_key provided
                placeholder = "<<Add Your Public Key File's content here>>"
                if public_key and placeholder in line:
                    line = line.replace(placeholder, public_key)

                commands[current_section] += line + "\n"
        elif line.startswith("```sql {#"):
            in_named_sql = True
            current_section = line.split("{#")[1].split("}")[0]
    return {
        k: [c.strip("\n") for c in v.split(";") if c.strip() != ""]
        for k, v in commands.items()
    }


def get_raw_sql_blocks(md, public_key=None):
    """Extract named SQL blocks as raw text, preserving comments and blank lines.

    Unlike get_sql_commands(), which strips comments and splits the block into
    individual statements for execution, this keeps each block exactly as written
    so students can paste it straight into a Snowflake worksheet.
    """
    blocks = OrderedDict()
    current_section = None
    in_named_sql = False
    placeholder = "<<Add Your Public Key File's content here>>"

    for line in md.split("\n"):
        if in_named_sql:
            if line.startswith("```"):
                in_named_sql = False
                continue
            if public_key and placeholder in line:
                line = line.replace(placeholder, public_key)
            blocks[current_section] = blocks.get(current_section, "") + line + "\n"
        elif line.startswith("```sql {#"):
            in_named_sql = True
            current_section = line.split("{#")[1].split("}")[0]

    return OrderedDict((k, v.strip("\n")) for k, v in blocks.items())


def load_manual_sql_blocks(public_key):
    """Load every SQL block the automated setup would run, as pasteable raw SQL."""
    blocks = OrderedDict()

    with open(os.path.join(CURRENT_DIR, "course-resources.md"), "r") as file:
        blocks.update(get_raw_sql_blocks(file.read().rstrip(), public_key))

    capstone_path = os.path.join(CURRENT_DIR, "capstone-resources.md")
    if os.path.exists(capstone_path):
        with open(capstone_path, "r") as file:
            blocks.update(get_raw_sql_blocks(file.read().rstrip(), public_key))
    else:
        logging.error(f"Capstone file not found at {capstone_path}")

    return blocks


def build_manual_sql_script(public_key):
    """Join every setup block into one script students can copy in a single go.

    Section headers become SQL comments so the script stays valid when pasted
    into a Snowflake worksheet and executed as a whole.
    """
    blocks = load_manual_sql_blocks(public_key)

    parts = []
    for index, (section, sql) in enumerate(blocks.items(), start=1):
        title = sql_sections.get(section, section)
        parts.append(
            f"-- ============================================================\n"
            f"-- Step {index}: {title}\n"
            f"-- ============================================================\n"
            f"{sql}"
        )

    return "\n\n".join(parts)


hello_msg_default = """
# dbt (Data Build Tool) Bootcamp
## Snowflake and Profile Setup Helper

Hi there!

This webapp helps you getting started with dbt, Snowflake and Preset, the BI tool we'll use in the course.

**We'll do the following**:

* **Step 1)** Snowflake Setup - We'll generate a keypair, set up your Snowflake account and import the raw AirBnB tables **and the AIRSTATS capstone database**.
* **Step 2)** Configuration Files - We'll download the configuration files needed for your dbt project and Preset.

On with the setup!
"""

hello_msg_ceu = """
# CEU Modern Data Platforms
## Snowflake and Profile Setup Helper

Hi there!

This webapp helps you getting started with dbt, Snowflake and Preset for the **CEU Modern Data Platforms** course.

**We'll do the following**:

* **Step 1)** Snowflake Setup - We'll generate a keypair, set up your Snowflake account and import the raw AirBnB tables **and the AIRSTATS capstone database**.
* **Step 2)** Configuration Files - We'll download the configuration files needed for your dbt project and Preset.

On with the setup!
"""

hello_msg_capstone = """
# dbt (Data Build Tool) Bootcamp
## Set up Capstone (AIRSTATS Database)

**This mode is only for students who started the course before 14 March 2026.**

If you started after that date, the AIRSTATS capstone database was already set up as part of the standard setup. You don't need to run this again.

**Not sure?** Log in to your Snowflake account and check if you already have an `AIRSTATS` database. If you do, you're all set!

This wizard will:
* Connect to your Snowflake account
* Create the `AIRSTATS` database with airport data tables
* Grant the necessary permissions to your `dbt` and `preset` users
"""

logging.root.setLevel(logging.INFO)
logger = getLogger(__name__)
logger.Formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
)


GITHUB_REPO_URL = "https://github.com/zoltanctoth/dbtlearn-snowflake-importer"


def get_build_info() -> str:
    """Get build info for footer display."""
    commit_full = os.environ.get("GIT_COMMIT", "local")
    commit_short = commit_full[:7]
    if commit_full not in ("local", "unknown"):
        commit_link = f'<a href="{GITHUB_REPO_URL}/commit/{commit_full}" target="_blank" style="color: #888;">{commit_short}</a>'
    else:
        commit_link = commit_short
    # HOSTNAME is automatically set by Docker to the container ID
    container_id = os.environ.get("HOSTNAME", "unknown")[:12]
    return f"commit: {commit_link} | container: {container_id} | started: {APP_START_TIME} UTC"


# Shown in the account field until the student types their own identifier.
ACCOUNT_PLACEHOLDER = "xxxxxx-xxxxxxxx"

ACCOUNT_INPUT_LABEL = (
    "Snowflake account — e.g. `frgcsyo-ie17820` or `frgcsyo-ie17820.aws`, from your "
    "Snowflake registration email. **Not your username.** You can also paste the full URL:"
)


ACCOUNT_CHECK_TIMEOUT_SECONDS = 10


def check_snowflake_account_exists(account):
    """Ask Snowflake whether an account identifier belongs to a real account.

    Snowflake redirects `https://<account>.snowflakecomputing.com/` to the login
    console for accounts that exist and serves a 404 for ones that don't, so this
    needs no credentials. DNS is not usable for this — Snowflake resolves
    nonexistent accounts too.

    Returns (exists, detail). ``exists`` is None when we couldn't tell (network
    error, unexpected status); that must never be reported as a bad account.
    """
    url = f"https://{account}.snowflakecomputing.com/"
    try:
        response = requests.get(
            url, timeout=ACCOUNT_CHECK_TIMEOUT_SECONDS, allow_redirects=False
        )
    except requests.RequestException as e:
        logging.warning(f"Account check failed for {account}: {e}")
        return None, str(e)

    if response.status_code == 404:
        return False, f"HTTP 404 from {url}"
    if response.status_code < 400:
        return True, f"HTTP {response.status_code} from {url}"
    return None, f"HTTP {response.status_code} from {url}"


def _render_account_check(key, account, is_valid):
    """Check the account identifier and render the verdict, plus an explicit button.

    Leaving the field reruns the script with the new value, which is enough to
    check it — students shouldn't have to press anything to find out their account
    is wrong. The button is kept for anyone who wants an explicit action, and it
    doubles as the commit path for a value typed but never blurred.

    The result is remembered alongside the account it was produced for, so a
    verdict is never shown against an identifier it wasn't produced for, and each
    account costs at most one request no matter how many reruns follow.
    """
    result_key = f"{key}_check_result"

    # Deliberately never disabled: clicking the button is what commits a freshly
    # typed value, so a disabled button would trap students who type and click
    # without pressing Enter first.
    clicked = st.button(
        "Check account identifier",
        key=f"{key}_check_button",
        help="Checks that this account exists. No password is sent.",
    )

    if clicked and not is_valid:
        st.session_state.pop(result_key, None)
        st.warning("Enter your Snowflake account first.")
        return

    remembered = st.session_state.get(result_key)
    is_unchecked = not remembered or remembered[0] != account
    if is_valid and (clicked or is_unchecked):
        with st.spinner("Checking..."):
            exists, detail = check_snowflake_account_exists(account)
        remembered = (account, exists, detail)
        st.session_state[result_key] = remembered

    if not remembered or remembered[0] != account:
        return

    _, exists, _detail = remembered
    if exists is True:
        st.success(f"`{account}` is a valid Snowflake account.")
    elif exists is False:
        st.error(
            f"Snowflake doesn't know an account called `{account}`. "
            "Check your registration email — it may need a region suffix like `.aws`."
        )
    else:
        st.warning("Couldn't reach Snowflake to check. You can still continue.")


def account_is_entered(account_raw):
    """True once the account field holds something other than the untouched placeholder.

    ACCOUNT_PLACEHOLDER is itself a syntactically valid account identifier, so a
    format check alone cannot tell "never filled in" from "filled in correctly".
    """
    return account_raw.strip() not in ("", ACCOUNT_PLACEHOLDER)


def render_account_input(key):
    """Render the Snowflake account field with URL extraction and validation.

    Shared by the credentials form and the manual-SQL page so both accept the same
    inputs (bare identifier, `.aws` suffix, or a pasted registration URL).

    Returns (account, is_valid). ``is_valid`` is False while the field still holds
    the untouched placeholder — which matches the account pattern, so callers that
    require a real account cannot rely on is_valid_snowflake_account() alone.
    """
    # Carry the account across screens; fall back to the env var (local dev / tests).
    default_account = st.session_state.get(
        "snowflake_account"
    ) or os.environ.get("SNOWFLAKE_ACCOUNT", ACCOUNT_PLACEHOLDER)

    account_raw = st.text_input(ACCOUNT_INPUT_LABEL, default_account, key=key)
    account = extract_snowflake_account(account_raw)

    is_entered = account_is_entered(account_raw)
    is_valid = is_entered and is_valid_snowflake_account(account)

    # Store the account in session state for later use. Kept unconditional so the
    # manual-SQL page inherits whatever was typed on the credentials form.
    st.session_state.snowflake_account = account

    if is_entered and not is_valid:
        st.warning(
            "This doesn't look like a valid Snowflake account format. Please check your account identifier."
        )
    elif is_valid and account != account_raw:
        # Show the extracted account identifier if it's different from the input
        st.info(f"Using account identifier: `{account}`")

    _render_account_check(key, account, is_valid)

    return account, is_valid


def render_credentials_form(key_prefix, submit_label, submit_key):
    """Render the Snowflake credentials form and its submit button.

    Returns (submitted, hostname, username, password, passcode). ``submitted`` is
    False when the account field is empty, still holds the placeholder, or isn't a
    valid identifier — the form reports the problem itself, so callers never have to
    guard against connecting to an account that cannot exist.

    The credential fields live in an ``st.form`` for one reason: a bare
    ``st.text_input`` only hands its value to the server when it loses focus, and
    that commit races the click on a plain ``st.button``. Type a password, click
    straight through to the button, and the click's rerun can reach the server
    before the field's — the script then sees an empty password even though the
    student is looking at a filled-in field. A form submits every field it holds
    together with the click, so the race cannot happen. It also means Enter
    submits, which is what students try first anyway.

    The account field stays outside the form on purpose: it validates as soon as
    focus leaves it, and form fields are silent until submit.

    Args:
        key_prefix: Prefix for widget keys to avoid conflicts when rendered in multiple tabs.
        submit_label: Label for the submit button.
        submit_key: Widget key for the submit button.
    """
    registry.register("snowflake", "snowflake.sqlalchemy", "dialect")

    # Check environment for credentials (priority: env vars, then defaults)
    env_username = os.environ.get("SNOWFLAKE_USERNAME", "admin")
    env_password = os.environ.get("SNOWFLAKE_PASSWORD", "")

    st.info(
        "Now let's add your Snowflake Account name and Admin Credentials so we can set up the permissions and the datasets for you."
    )
    hostname, account_valid = render_account_input(f"{key_prefix}input_snowflake_account")

    with st.form(key=f"{key_prefix}credentials_form", border=False):
        username = st.text_input(
            "Snowflake username (change this is you didn't set it to `admin` at registration):",
            env_username,
            key=f"{key_prefix}input_snowflake_username",
        )
        password = st.text_input(
            "Snowflake Password:",
            env_password,
            type="password",
            key=f"{key_prefix}input_snowflake_password",
        )

        st.warning(
            "**Multi Factor Authentication (MFA)**\n\n"
            "* **Duo app:** leave the code empty and approve the notification on your phone.\n"
            "* **Authenticator app:** enter your current 6-digit code.\n\n"
            "No MFA yet? Try to leave the MFA box below empty, and it's not working, go to your snowflake and click: your account name (bottom left) → **Account** → "
            "**Authentication** → **Add authentication method** → **Authenticator** "
            "(not Passkey)."
        )

        passcode_input = st.text_input(
            "6-digit MFA code (leave empty for Duo push or if MFA is not enabled on your Snowflake account):",
            max_chars=6,
            key=f"{key_prefix}input_totp_passcode",
        )

        submitted = st.form_submit_button(
            submit_label,
            type="primary",
            use_container_width=True,
            key=submit_key,
        )

    # An empty field means "no TOTP" — we must not pass an empty passcode to Snowflake.
    passcode = passcode_input.strip() or None

    # A submit that cannot possibly succeed is not reported as one. The account field
    # starts out holding ACCOUNT_PLACEHOLDER, which passes the format check, so a
    # student who fills in only a password used to sail straight through to a real
    # login attempt against xxxxxx-xxxxxxxx.snowflakecomputing.com — a guaranteed 404
    # that reads to them as a broken tool. Swallowing the submit here rather than at
    # each call site means no caller can forget the check.
    if submitted and not account_valid:
        account_raw = st.session_state.get(f"{key_prefix}input_snowflake_account", "")
        if not account_is_entered(account_raw):
            st.error(
                "**Please fill in your Snowflake account identifier above.**\n\n"
                f"The field still holds the `{ACCOUNT_PLACEHOLDER}` placeholder. Replace it "
                "with the account from your Snowflake registration email — it looks like "
                "`frgcsyo-ie17820` — or paste the full Snowflake URL and we'll pick the "
                "identifier out of it."
            )
        else:
            st.error(
                f"**`{account_raw.strip()}` doesn't look like a Snowflake account "
                "identifier.**\n\nPlease correct it above and press "
                f"**{submit_label}** again."
            )
        submitted = False

    return submitted, hostname, username, password, passcode


FALLBACK_APP_URL = "https://udemy-dbt-setup.streamlit.app/"
PRIMARY_HOST = "dbtsetup.nordquant.com"


def _render_snowflake_fallback_notice():
    """Show a notice + CTA suggesting the Streamlit Cloud fallback when Snowflake connection fails."""
    st.warning(
        f"This might indicate that Snowflake blocked our server. "
        f"Please try again at [{FALLBACK_APP_URL}]({FALLBACK_APP_URL})."
    )
    st.link_button("Open the alternative setup app", FALLBACK_APP_URL, type="primary")


def _notify_slack_of_connection_error(session_id, error_type, hostname, username, error):
    """Post a Slack alert when Snowflake connection fails on the primary host.

    No-op unless SLACK_WEBHOOK_URL is set and the request was served from PRIMARY_HOST.
    """
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook_url:
        return
    try:
        request_host = (st.context.headers.get("host") or "").split(":")[0].lower()
    except Exception:
        request_host = ""
    if request_host != PRIMARY_HOST:
        return
    error_orig = getattr(error, "orig", error)
    payload = {
        "text": (
            f":warning: Snowflake connection error on `{PRIMARY_HOST}`\n"
            f"*Error type:* {error_type}\n"
            f"*Account:* `{hostname}`\n"
            f"*Username:* `{username}`\n"
            f"*Session:* `{session_id}`\n"
            f"*Error:* ```{str(error_orig)[:1500]}```"
        )
    }
    try:
        requests.post(webhook_url, json=payload, timeout=5)
    except Exception as slack_err:
        logging.warning(f"{session_id}: Failed to post Slack notification: {slack_err}")


def _is_account_not_found(error):
    """True when Snowflake 404s the login request, i.e. the account identifier doesn't resolve.

    Every Snowflake account is served from its own hostname, so an identifier that
    doesn't exist fails as a 404 on /session/v1/login-request (error 290404) long
    before any credential is checked. It always means a mistyped account — never a
    bad password, and never a problem on our side.
    """
    text = str(getattr(error, "orig", error)).lower()
    return "290404" in text or ("404 not found" in text and "login-request" in text)


def _handle_account_not_found(session_id, hostname, username, error):
    """Tell the student their account identifier is mistyped. Returns None, like its callers.

    No Slack alert: a 404 is always a typo in the student's own input, so alerting
    on it only buries the failures worth waking up for — the ones where Snowflake
    is refusing *our server*. It stays in the logs, where the volume is a useful
    signal about how confusing the account field is without paging anyone.

    Deliberately skips _render_snowflake_fallback_notice() too: the fallback app
    would 404 on the same identifier, so pointing there sends the student in a circle.
    """
    st.error(
        f"**Snowflake doesn't know an account called `{hostname}`.**\n\n"
        f"That almost always means `{hostname}` is mistyped — it is not a password "
        "problem. Please check it character by character against your Snowflake "
        "registration email and try again.\n\n"
        "* It looks like `frgcsyo-ie17820`: two parts, one hyphen. It is **not** your username.\n"
        "* Some accounts need a region suffix, e.g. `frgcsyo-ie17820.aws`.\n"
        "* You can also paste the full Snowflake URL from your browser — we'll pick the "
        "identifier out of it."
    )
    logging.warning(
        f"{session_id}: Snowflake account not found (404). Account: {hostname}, Username: {username}: {error}"
    )
    return None


def _connect_to_snowflake(session_id, hostname, username, password, passcode):
    """Attempt to connect to Snowflake. Returns (connection_cm, connection) or displays error and returns None."""
    try:
        with st.status("Connecting to Snowflake"):
            connection_cm = get_snowflake_connection(hostname, username, password, passcode)
            connection = connection_cm.__enter__()
        return connection_cm, connection
    except InterfaceError as e:
        if _is_account_not_found(e):
            return _handle_account_not_found(session_id, hostname, username, e)
        st.error(
            f"""Error connecting to Snowflake. This usually means that the snowflake account is invalid.
            Please verify the snowflake account and try again.\n\nOriginal Error: \n\n{e.orig}"""
        )
        _render_snowflake_fallback_notice()
        _notify_slack_of_connection_error(session_id, "InterfaceError", hostname, username, e)
        logging.warning(
            f"{session_id}: Error connecting to Snowflake. Account: {hostname}, Username: {username}: {e}"
        )
        return None
    except DatabaseError as e:
        if _is_account_not_found(e):
            return _handle_account_not_found(session_id, hostname, username, e)
        print(e)
        error_str = str(e.orig) if hasattr(e, 'orig') else str(e)

        # Check if this is a TOTP MFA error
        lowered_error = error_str.lower()
        is_totp_required = (
            "TOTP is required" in error_str or "MFA with TOTP" in error_str
        )
        # Newer Snowflake MFA enforcement: the user is enrolled in an MFA method
        # (e.g. Duo Push, SMS, passkey) that drivers can't use. Message reads:
        # "MFA authentication is required, but none of your current MFA methods are
        #  supported for programmatic authentication."
        is_unsupported_mfa = (
            "mfa" in lowered_error and "programmatic" in lowered_error
        )

        if is_totp_required:
            st.error(
                "**Your Snowflake account needs an MFA code.**\n\n"
                "Enter your current 6-digit code above and press **Start Setup** again.\n\n"
                f"Original Error:\n\n{e.orig}"
            )
        elif is_unsupported_mfa:
            st.error(
                "**Your MFA method can't be used by this tool** — usually a Passkey "
                "(Touch ID / Face ID), which only works in the Snowflake web UI.\n\n"
                "In Snowflake: your account name (bottom left) → **Account** → "
                "**Authentication** → **Add authentication method** → **Authenticator** "
                "(not Passkey). Then enter the 6-digit code above.\n\n"
                "Or use **Skip the automated setup** above and run the commands yourself.\n\n"
                f"Original Error:\n\n{e.orig}"
            )
        else:
            st.error(
                f"Error connecting to Snowflake. This usually means that the snowflake username or password you provided is not valid. Please correct them and retry by pressing the Start Setup button.\n\nOriginal Error:\n\n{e.orig}"
            )
        logging.warning(
            f"{session_id}: Error connecting to Snowflake. Account name: {hostname}\n Original Error: {e}"
        )
        return None
    except Exception as e:
        if _is_account_not_found(e):
            return _handle_account_not_found(session_id, hostname, username, e)

        st.error(
            f"Error connecting to Snowflake.\n\nOriginal Error:\n\n{e}\n\nStacktrace:\n\n{traceback.format_exc()}"
        )
        _render_snowflake_fallback_notice()
        _notify_slack_of_connection_error(session_id, type(e).__name__, hostname, username, e)
        logging.warning(
            f"{session_id}: Error connecting to Snowflake. Account name: {hostname}\n Original Error: {e}\nStacktrace:\n{traceback.format_exc()}"
        )
        return None


def _execute_sql_sections(session_id, connection, sql_commands, sections_to_run):
    """Execute SQL sections and verify tables. Returns True on success."""
    try:
        # Log sections being executed for debugging
        print(f"DEBUG [{session_id}]: === EXECUTING SQL SECTIONS ===")
        print(f"DEBUG [{session_id}]: Sections to execute: {sections_to_run}")
        logging.info(f"{session_id}: SQL sections to execute: {sections_to_run}")

        for section in sections_to_run:
            commands = sql_commands[section]
            print(f"DEBUG [{session_id}]: EXECUTING section: {section} with {len(commands)} commands")
            logging.info(f"{session_id}: Executing section: {section} with {len(commands)} commands")
            with st.status(
                sql_sections[section]
            ) as internal_status_spinner:
                for command in commands:
                    st.write(f"Executing command: `{command}`")
                    connection.execute(text(command))
                    connection.commit()

        return True
    except Exception as e:
        st.error(
            f"Error executing command.\n\nOriginal Error:\n\n{e}\n\nTraceback:\n\n{traceback.format_exc()}"
        )
        logging.warning(
            f"{session_id}: Error executing SQL. Account name: {st.session_state.get('snowflake_account')}\n Original Error: {e}"
        )
        return False


def _verify_tables(connection, tables):
    """Verify that tables have rows. Returns True if all tables have data."""
    for table in tables:
        result = connection.execute(
            text(f"SELECT COUNT(*) FROM {table}")
        )
        count = result.fetchone()[0]
        if count == 0:
            st.error(
                f"Table {table} has no rows. This is unexpected. Please check the logs and try again."
            )
            return False
    return True


def _verify_user_connections(session_id, conn_builder):
    """Verify dbt and preset user connections via a caller-supplied builder.

    ``conn_builder(login_name, role)`` must return a context manager that
    yields a SQLAlchemy Connection. This lets the same verification loop
    work for both keypair and password-based auth.
    """
    try:
        for login_name, role, schema in [
            ("dbt", "TRANSFORM", "RAW"),
            ("preset", "REPORTER", "DEV"),
        ]:
            with st.status(
                f"Verifying connection with {login_name} user"
            ) as internal_status_spinner:
                with conn_builder(login_name, role) as user_connection:
                    user_connection.execute(text(f"USE ROLE {role}"))
                    user_connection.execute(text("USE DATABASE AIRBNB"))
                    user_connection.execute(text(f"USE SCHEMA {schema}"))

                    if login_name == "dbt":
                        # Query RAW_LISTINGS table using dbt user. LIMIT 1 keeps
                        # this constant-memory: an unbounded SELECT * makes the
                        # Snowflake connector materialize the first result chunk
                        # and prefetch more on background threads, all to read
                        # the single row we need to prove the grants work.
                        result = user_connection.execute(
                            text("SELECT * FROM RAW.RAW_LISTINGS LIMIT 1")
                        )
                        result.fetchone()

                internal_status_spinner.success(
                    f"Success connecting as {login_name} user"
                )
        return True

    except Exception as e:
        error_msg = (
            f"Failed to connect with user or query "
            f"RAW_LISTINGS: {str(e)}"
        )
        st.error(error_msg)
        st.warning(
            "This might indicate an issue with the user "
            "setup or permissions."
        )
        logging.warning(
            f"{session_id}: user connection failed: {e}\nTraceback:\n{traceback.format_exc()}"
        )
        return False


def _render_preset_recovery_standalone():
    """Render the preset file recovery UI as a standalone tab."""
    st.markdown(
        "## Re-download Preset Instructions\n\n"
        "If you still have your `profiles.yml` but lost your "
        "`preset-instructions.md`, upload it here to regenerate it."
    )
    uploaded = st.file_uploader(
        "Upload your profiles.yml",
        type=["yml", "yaml"],
        key="upload_profiles_yml",
    )
    if uploaded is not None:
        try:
            content = uploaded.read().decode("utf-8")
            account, key = parse_profiles_yml(content)
            preset = generate_preset_instructions(account, key)
            st.download_button(
                label="Download preset-instructions.md",
                data=preset,
                file_name="preset-instructions.md",
                mime="text/markdown",
                key="btn_download_recovered_preset",
            )
            st.success("Preset instructions regenerated successfully!")
        except ValueError as e:
            st.error(f"Could not parse profiles.yml: {e}")


def _render_env_scripts_standalone():
    """Render the env-script download UI as a standalone tab.

    Students upload the profiles.yml they got from the importer and download
    a shell-native script (bash or PowerShell) that exports the Snowflake env
    vars used by profiles.withenvs.yml in the dev-repo.
    """
    st.markdown("## Download env-var scripts")
    uploaded = st.file_uploader(
        "Upload your profiles.yml",
        type=["yml", "yaml"],
        key="upload_profiles_yml_envscripts",
    )
    if uploaded is not None:
        try:
            content = uploaded.read().decode("utf-8")
            values = parse_profiles_yml_full(content)
            sh_script = generate_set_env_sh(values)
            ps1_script = generate_set_env_ps1(values)

            st.info(
                "Save the downloaded file in your `course/` repo root — "
                "alongside the `airbnb/` folder, not inside it."
            )
            col_sh, col_ps1 = st.columns(2)
            with col_sh:
                st.download_button(
                    label="Download set-env.sh (Mac/Linux)",
                    data=sh_script,
                    file_name="set-env.sh",
                    mime="text/x-shellscript",
                    key="btn_download_set_env_sh",
                )
            with col_ps1:
                st.download_button(
                    label="Download set-env.ps1 (Windows)",
                    data=ps1_script,
                    file_name="set-env.ps1",
                    mime="text/plain",
                    key="btn_download_set_env_ps1",
                )
            st.success("Environment-variable-setter scripts generated successfully!")
        except ValueError as e:
            st.error(f"Could not parse profiles.yml: {e}")
    st.markdown(
        "### Where to save the downloaded file\n\n"
        "Save it in the **root of your `course` repo** — the same folder that "
        "contains the `airbnb/` directory, **not** inside `airbnb/`:\n\n"
        "```\n"
        "course/                  ← save set-env.sh / set-env.ps1 here\n"
        "├── airbnb/\n"
        "│   ├── dbt_project.yml\n"
        "│   └── profiles.withenvs.yml\n"
        "└── set-env.sh\n"
        "```\n\n"
        "### How to run it\n\n"
        "Open a terminal in the `course/` folder, then:\n\n"
        "- **macOS** (zsh / bash): `source ./set-env.sh`\n"
        "- **Linux** (bash): `source ./set-env.sh`\n"
        "- **Windows PowerShell**: `. .\\set-env.ps1`\n"
        "  - First time only, per machine: "
        "`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`\n\n"
        "**Windows note:** the script **must run in PowerShell** — the old "
        "`cmd.exe` (Command Prompt) does not understand `.ps1` files or the "
        "`$env:` syntax. The good news: VS Code's default integrated terminal "
        "on Windows is PowerShell, so opening **Terminal → New Terminal** "
        "inside VS Code works out of the box. If you opened Command Prompt "
        "by mistake, just type `powershell` to drop into a PowerShell session.\n\n"
        "**Reminders:**\n"
        "- The env vars only live in the **current terminal session** — open "
        "a new terminal and you'll need to source the script again.\n"
        "- The script contains your Snowflake credentials. **Do not commit it** "
        "— add `set-env.sh` and `set-env.ps1` to your `.gitignore`."
    )


# Step index of the "run the SQL yourself" screen in the standard flow.
STEP_MANUAL_SQL = 3

# Walkthrough recording. H.264 rather than the source GIF: same silent loop,
# ~20x smaller. Note it goes through st.video() rather than Streamlit's static
# file serving — that handler only sets real MIME types for an allow-list of
# extensions (images, fonts, pdf, json) and serves .mp4 as text/plain, which
# browsers refuse to play.
SNOWFLAKE_PASTE_VIDEO = "snowflake-add.mp4"


def _ensure_keypair():
    """Generate the session keypair if we don't have one yet, without any fanfare.

    Almost no student knows or cares what a keypair is — the setup just needs one,
    so it happens quietly in the background.
    """
    if "keypair" not in st.session_state:
        st.session_state.keypair = generate_keys("q")
    return st.session_state.keypair


def _render_keypair_downloads():
    """Offer the keypair files behind a deliberately quiet, collapsed expander.

    Only students who came looking for the keys should notice this.
    """
    keypair = st.session_state.keypair

    with st.expander("Keys generated"):
        st.caption("Used automatically during setup. Download only if you want a backup.")
        st.download_button(
            label="Download Private Key (rsa_key.p8)",
            data=keypair.private_key,
            file_name="rsa_key.p8",
            mime="text/plain",
            key="btn_download_private_key",
        )
        st.download_button(
            label="Download Public Key (rsa_key.pub)",
            data=keypair.public_key,
            file_name="rsa_key.pub",
            mime="text/plain",
            key="btn_download_public_key",
        )


def _render_static_video(filename, caption=None):
    """Embed a walkthrough video that loops silently, like the GIF it replaced.

    ``muted`` is what makes browsers allow autoplay. Skipped when the file is
    missing, so a packaging slip degrades to a page without a video rather
    than a broken one.
    """
    path = os.path.join(CURRENT_DIR, "static", filename)
    if not os.path.exists(path):
        logging.error(f"Static asset not found: static/{filename}")
        return

    st.video(path, loop=True, autoplay=True, muted=True)
    if caption:
        st.caption(caption)


def _render_manual_sql_page():
    """Render the manual-SQL screen: the exact commands the automated setup runs.

    Students who can't get past MFA (e.g. passkey-only accounts) paste these into
    a Snowflake worksheet themselves, then continue to the download page. The
    public key baked into the SQL comes from the same session keypair that ends up
    in profiles.yml, so both must be taken from this same browser session.
    """
    st.markdown("### Manual Snowflake Setup")

    if st.button(
        "Back to the automated setup", type="secondary", key="btn_manual_back"
    ):
        st.session_state.step_standard = 1
        st.rerun()

    # The keypair is normally generated in step 1, but this page can be reached
    # directly (e.g. after a page reload), so make sure we have one.
    keypair = _ensure_keypair()

    st.warning(
        "**Don't close this tab** — open Snowflake in a new tab, or this setup stops working."
    )

    st.divider()

    st.subheader("1) Add your Snowflake Account")
    account, account_is_valid = render_account_input("manual_input_snowflake_account")

    st.divider()

    st.subheader("2) Copy this Snowflake Command and Paste / Execute in Snowflake")

    combined_sql = build_manual_sql_script(keypair.public_key)
    if not combined_sql:
        st.error(
            "Could not load the SQL commands. Please contact support or use the "
            "automated setup."
        )
        return

    _render_static_video(
        SNOWFLAKE_PASTE_VIDEO,
        caption="Paste into a Snowflake worksheet, select all, press play.",
    )
    st.markdown("Copy the whole block (copy button in the top right of the box):")
    st.code(combined_sql, language="sql")

    st.divider()

    st.subheader("3) Download your dbt config files")

    if st.button(
        "Commands executed in Snowflake, download dbt config files",
        type="primary",
        use_container_width=True,
        key="btn_manual_done",
    ):
        if not account_is_valid:
            st.error(
                "Please enter a valid Snowflake account above — it's needed to "
                "generate your `profiles.yml`."
            )
            return
        st.session_state.snowflake_account = account
        st.session_state.step_standard = 2
        st.rerun()


def standard_setup(session_id):
    """Standard setup flow: landing -> Snowflake setup (with keypair) -> download config files."""
    is_ceu_mode = st.session_state.course_mode == "ceu"

    if "step_standard" not in st.session_state:
        st.session_state.step_standard = 0

    # Step 0: Landing Page
    if st.session_state.step_standard == 0:
        hello_msg = hello_msg_ceu if is_ceu_mode else hello_msg_default
        st.markdown(hello_msg)

        if st.button(
            "Start Setup Process",
            type="primary",
            use_container_width=True,
            key="btn_start_setup",
        ):
            st.session_state.step_standard = 1
            st.rerun()

    # Step 1: Snowflake Setup (keypair generation + credentials + SQL execution)
    elif st.session_state.step_standard == 1:
        snowflake_setup_complete = False
        st.markdown("### Step 1: Snowflake Setup")

        if st.button("Back to Welcome", type="secondary", key="btn_back_to_welcome"):
            st.session_state.step_standard = 0
            st.rerun()

        _ensure_keypair()
        _render_keypair_downloads()

        # Credentials form
        submitted, hostname, username, password, passcode = render_credentials_form(
            key_prefix="std_",
            submit_label="Start Setup",
            submit_key="btn_start_snowflake_setup",
        )

        if submitted:
            if len(password) == 0:
                st.error("Please provide a password")
                return

            # Load and process SQL commands with public key substitution
            with open(CURRENT_DIR + "/course-resources.md", "r") as file:
                md = file.read().rstrip()
            public_key = st.session_state.keypair.public_key
            sql_commands = get_sql_commands(md, public_key)

            # Always load capstone SQL
            capstone_path = CURRENT_DIR + "/capstone-resources.md"
            print(f"DEBUG [{session_id}]: Loading capstone from {capstone_path}")
            logging.info(f"{session_id}: Loading capstone from {capstone_path}, exists={os.path.exists(capstone_path)}")
            if os.path.exists(capstone_path):
                with open(capstone_path, "r") as file:
                    capstone_md = file.read().rstrip()
                capstone_commands = get_sql_commands(capstone_md, public_key)
                print(f"DEBUG [{session_id}]: Capstone sections loaded: {list(capstone_commands.keys())}")
                logging.info(f"{session_id}: Capstone sections loaded: {list(capstone_commands.keys())}")
                sql_commands = {**sql_commands, **capstone_commands}
            else:
                print(f"DEBUG [{session_id}]: ERROR - capstone file does not exist!")
                logging.error(f"{session_id}: Capstone file not found at {capstone_path}")

            # Connect to Snowflake
            result = _connect_to_snowflake(session_id, hostname, username, password, passcode)
            if result is None:
                return
            connection_cm, connection = result

            try:
                with st.status(
                    "Setting up your Snowflake account (this can take up to 2 minutes)"
                ) as status_spinner:
                    # Execute all SQL sections
                    sections_to_run = [s for s in sql_commands.keys()]
                    if not _execute_sql_sections(session_id, connection, sql_commands, sections_to_run):
                        status_spinner.update(
                            label="Error executing command",
                            state="error",
                            expanded=True,
                        )
                        return

                    # Verify AIRBNB tables
                    airbnb_tables = [
                        "AIRBNB.RAW.RAW_LISTINGS",
                        "AIRBNB.RAW.RAW_HOSTS",
                        "AIRBNB.RAW.RAW_REVIEWS",
                    ]
                    if not _verify_tables(connection, airbnb_tables):
                        return

                    # Verify AIRSTATS tables
                    airstats_tables = [
                        "AIRSTATS.RAW.AIRPORTS",
                        "AIRSTATS.RAW.AIRPORT_COMMENTS",
                        "AIRSTATS.RAW.RUNWAYS",
                    ]
                    if not _verify_tables(connection, airstats_tables):
                        return

                    # Verify user connections using keypair auth
                    private_key_pem = st.session_state.keypair.private_key
                    if not _verify_user_connections(
                        session_id,
                        lambda login, role: get_dbt_connection(
                            hostname, login, role, private_key_pem
                        ),
                    ):
                        status_spinner.update(
                            label="Error verifying user connections",
                            state="error",
                            expanded=True,
                        )
                        return

                    snowflake_setup_complete = True
            finally:
                connection_cm.__exit__(None, None, None)

            if snowflake_setup_complete:
                success_msg = "Snowflake Setup complete! Let's continue with downloading the configuration files!"
                st.toast(success_msg, icon="🔥")
                status_spinner.success(success_msg, icon="🔥")

                st.session_state.step_standard = 2
                if st.button(
                    "Download Configuration Files",
                    type="primary",
                    key="btn_goto_downloads",
                ):
                    st.rerun()

        st.divider()
        with st.expander(
            "⚠️ Can't get past MFA or the automated setup isn't working?", expanded=True
        ):
            st.markdown("You can run the Snowflake commands yourself instead:")
            if st.button(
                "Skip the automated setup — show me the Snowflake SQL commands",
                type="secondary",
                key="btn_show_manual_sql",
            ):
                st.session_state.step_standard = STEP_MANUAL_SQL
                st.rerun()

    # Step 2: Download Configuration Files
    elif st.session_state.step_standard == 2:
        st.markdown("### Step 1: Snowflake Setup - Completed")
        st.markdown("### Step 2: Download Configuration Files")

        # Add back button
        if st.button(
            "Back to Snowflake Setup", type="secondary", key="btn_back_to_snowflake"
        ):
            st.session_state.step_standard = 1
            st.rerun()

        st.markdown(
            """Download the configuration files needed for dbt and Preset integration.

 * `profiles.yml`: contains your dbt connection configuration which you'll need to copy to your dbt project folder later.
 * `preset-instructions.md`: contains instructions for connecting to Preset, which we'll cover later in the course."""
        )

        # Get the keypair and account info from session state
        if "keypair" not in st.session_state:
            st.error("No keypair found. Please go back and generate keys first.")
            return

        if "snowflake_account" not in st.session_state:
            st.error(
                "No Snowflake account found. Please go back and complete "
                "Snowflake setup first."
            )
            return

        keypair = st.session_state.keypair
        snowflake_account = st.session_state.snowflake_account

        # Generate the files
        profiles_content = generate_profiles_yml(
            snowflake_account, keypair.private_key_pem_text
        )
        preset_content = generate_preset_instructions(
            snowflake_account, keypair.private_key_pem_text
        )

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("#### ① dbt profiles.yml")
            st.markdown("This file contains your dbt connection configuration.")
            st.download_button(
                label="Download profiles.yml",
                data=profiles_content,
                file_name="profiles.yml",
                mime="text/yaml",
                key="btn_download_profiles",
            )

        with col2:
            st.markdown("#### ② Preset Instructions")
            st.markdown("This file contains instructions for connecting to Preset.")
            st.download_button(
                label="Download preset-instructions.md",
                data=preset_content,
                file_name="preset-instructions.md",
                mime="text/markdown",
                key="btn_download_preset",
            )

        st.success("Configuration files ready for download!")
        st.info(
            "Please download **both** files above. You'll need them to configure "
            "dbt and Preset with your Snowflake database."
        )

        st.toast("Configuration files ready for download!", icon="🔥")
        st.success(
            "Once you downloaded both files, you can go back to the course and continue with the setup!"
        )

    # Step 3: Manual SQL (skip the automated setup)
    elif st.session_state.step_standard == STEP_MANUAL_SQL:
        _render_manual_sql_page()


def capstone_setup(session_id):
    """Capstone-only setup flow: landing -> credentials + AIRSTATS SQL execution."""

    if "step_capstone" not in st.session_state:
        st.session_state.step_capstone = 0

    # Step 0: Capstone Landing Page
    if st.session_state.step_capstone == 0:
        st.markdown(hello_msg_capstone)

        if st.button(
            "Set up AIRSTATS Capstone",
            type="primary",
            use_container_width=True,
            key="btn_start_capstone",
        ):
            st.session_state.step_capstone = 1
            st.rerun()

    # Step 1: Credentials + AIRSTATS Setup
    elif st.session_state.step_capstone == 1:
        capstone_setup_complete = False
        st.markdown("### Set up AIRSTATS Capstone Database")

        if st.button("Back to Welcome", type="secondary", key="btn_capstone_back_to_welcome"):
            st.session_state.step_capstone = 0
            st.rerun()

        # Credentials form
        submitted, hostname, username, password, passcode = render_credentials_form(
            key_prefix="cap_",
            submit_label="Start Capstone Setup",
            submit_key="btn_start_capstone_setup",
        )

        if submitted:
            if len(password) == 0:
                st.error("Please provide a password")
                return

            # Load capstone SQL only
            capstone_path = CURRENT_DIR + "/capstone-resources.md"
            if not os.path.exists(capstone_path):
                st.error("Capstone resource file not found. Please contact support.")
                logging.error(f"{session_id}: Capstone file not found at {capstone_path}")
                return

            with open(capstone_path, "r") as file:
                capstone_md = file.read().rstrip()
            sql_commands = get_sql_commands(capstone_md)

            # Connect to Snowflake
            result = _connect_to_snowflake(session_id, hostname, username, password, passcode)
            if result is None:
                return
            connection_cm, connection = result

            try:
                with st.status(
                    "Setting up AIRSTATS capstone database"
                ) as status_spinner:
                    # Execute capstone SQL sections
                    sections_to_run = [s for s in sql_commands.keys()]
                    if not _execute_sql_sections(session_id, connection, sql_commands, sections_to_run):
                        status_spinner.update(
                            label="Error executing command",
                            state="error",
                            expanded=True,
                        )
                        return

                    # Verify AIRSTATS tables
                    airstats_tables = [
                        "AIRSTATS.RAW.AIRPORTS",
                        "AIRSTATS.RAW.AIRPORT_COMMENTS",
                        "AIRSTATS.RAW.RUNWAYS",
                    ]
                    if not _verify_tables(connection, airstats_tables):
                        return

                    capstone_setup_complete = True
            finally:
                connection_cm.__exit__(None, None, None)

            if capstone_setup_complete:
                success_msg = "AIRSTATS Capstone Database setup complete!"
                st.toast(success_msg, icon="🔥")
                status_spinner.success(success_msg, icon="🔥")
                st.success(
                    "The AIRSTATS database has been created with airports, airport_comments, and runways tables. "
                    "You can now go back to the course and continue with the capstone project!"
                )


def main():
    session_id = streamlit_session_id()
    logger.info("Starting Streamlit app")

    # Detect course mode from query params
    course_mode = st.query_params.get("course", "default")
    if "course_mode" not in st.session_state:
        st.session_state.course_mode = course_mode
    is_ceu_mode = st.session_state.course_mode == "ceu"

    # Check for missing SQL resource files and display warnings
    resource_warnings = check_sql_resource_files(st.session_state.course_mode)
    for warning in resource_warnings:
        st.warning(f"⚠️ {warning}")

    if is_ceu_mode:
        # CEU: standard setup with CEU branding, no tabs
        standard_setup(session_id)
    else:
        tab_default, tab_capstone, tab_preset, tab_envscripts = st.tabs(
            [
                "Default Setup",
                "Capstone Only Setup",
                "Re-download Preset Instructions",
                "Download env-var scripts",
            ]
        )
        with tab_default:
            standard_setup(session_id)
        with tab_capstone:
            capstone_setup(session_id)
        with tab_preset:
            _render_preset_recovery_standalone()
        with tab_envscripts:
            _render_env_scripts_standalone()

    # Development info footer
    st.markdown(
        f"<div style='position: fixed; bottom: 0; right: 0; padding: 4px 8px; "
        f"font-size: 10px; color: #888; background: rgba(255,255,255,0.9);'>"
        f"{get_build_info()}</div>",
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    print("Starting Streamlit app")
    main()
