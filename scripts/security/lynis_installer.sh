#!/bin/bash
# ==========================================================
# ProxMenux - Lynis Security Audit Tool Installer
# ==========================================================
# Author      : MacRimi
# Copyright   : (c) 2024 MacRimi
# License     : GPL-3.0
#               https://github.com/MacRimi/ProxMenux/blob/main/LICENSE
# Version     : 1.0
# ==========================================================
# Description:
# Installs Lynis (CISOfy) from the official upstream GitHub
# repository so the host always gets the latest scanner, not the
# older Debian-packaged version. Provides install / update / run /
# uninstall actions through a unified menu. Hybrid runtime: works
# from terminal dialogs and from the ProxMenux web panel.
#
# Features:
#   - Clones https://github.com/CISOfy/lynis.git into /opt/lynis.
#   - Wrapper script at /usr/local/bin/lynis that cd's into /opt/lynis
#     before invoking ./lynis (Lynis requires being run from its own
#     directory).
#   - Detects the ProxMenux Git checkout and external Lynis executables,
#     including Debian's /usr/sbin/lynis, before showing the menu.
#   - Update action: 'git pull' inside /opt/lynis. Falls back to a
#     full reinstall if .git is missing.
#   - Run-audit action: launches 'lynis audit system --no-colors'
#     directly from the menu.
#   - Clean uninstall: removes verified ProxMenux files only;
#     Debian/CISOfy package installations are left untouched.
#   - Component status tracked in components_status.json.
# ==========================================================
# Hybrid script: works from terminal (dialog) and web panel (ScriptTerminalModal)

SCRIPT_TITLE="Lynis Security Audit Tool Installer"

LOCAL_SCRIPTS="/usr/local/share/proxmenux/scripts"
BASE_DIR="/usr/local/share/proxmenux"
UTILS_FILE="$BASE_DIR/utils.sh"
COMPONENTS_STATUS_FILE="$BASE_DIR/components_status.json"

export BASE_DIR
export COMPONENTS_STATUS_FILE

if [[ -f "$UTILS_FILE" ]]; then
  source "$UTILS_FILE"
fi

if [[ -f "$LOCAL_SCRIPTS/global/pmx_journal.sh" ]]; then
  source "$LOCAL_SCRIPTS/global/pmx_journal.sh"
fi

if [[ ! -f "$COMPONENTS_STATUS_FILE" ]]; then
  echo "{}" > "$COMPONENTS_STATUS_FILE"
fi

load_language
initialize_cache


# ==========================================================
# Detection
# ==========================================================
lynis_is_managed_wrapper() {
  # Compare every byte: matching two lines is not sufficient for ownership.
  [[ ! -L /usr/local/bin/lynis &&
     -f /usr/local/bin/lynis && -x /usr/local/bin/lynis ]] &&
    cmp -s /usr/local/bin/lynis <(printf '#!/bin/bash\ncd /opt/lynis && ./lynis "$@"\n')
}

lynis_managed_marker() {
  local marker=/opt/lynis/.proxmenux-managed
  [[ ! -L "$marker" && -f "$marker" ]] &&
    cmp -s "$marker" <(printf 'proxmenux-lynis-git-v1\n')
}

lynis_git_checkout() {
  # A directory named .git does not prove ProxMenux owns the checkout.
  [[ ! -L /opt/lynis && -d /opt/lynis/.git &&
     ! -L /opt/lynis/.git && -f /opt/lynis/lynis &&
     ! -L /opt/lynis/lynis && -x /opt/lynis/lynis ]] || return 1

  local remote
  remote="$(git -C /opt/lynis remote get-url origin 2>/dev/null)" || return 1
  case "$remote" in
    https://github.com/CISOfy/lynis|https://github.com/CISOfy/lynis.git|\
git@github.com:CISOfy/lynis|git@github.com:CISOfy/lynis.git) ;;
    *) return 1 ;;
  esac

  # New installs have an explicit marker. Legacy installs are recognized
  # only if their *complete* ProxMenux wrapper and Git remote both match.
  lynis_managed_marker || lynis_is_managed_wrapper
}

lynis_install_target_safe() {
  if [[ -e /usr/local/bin/lynis || -L /usr/local/bin/lynis ]]; then
    lynis_git_checkout && lynis_is_managed_wrapper
  else
    return 0
  fi
}

lynis_run() {
  if [[ "$LYNIS_SOURCE" == "git" && "$LYNIS_CMD" == "/opt/lynis/lynis" ]]; then
    (cd /opt/lynis && ./lynis "$@")
  else
    "$LYNIS_CMD" "$@"
  fi
}

detect_lynis() {
  LYNIS_INSTALLED=false
  LYNIS_VERSION=""
  LYNIS_CMD=""
  LYNIS_SOURCE="none"

  local path
  if lynis_git_checkout; then
    LYNIS_SOURCE="git"
    if lynis_is_managed_wrapper; then
      LYNIS_CMD=/usr/local/bin/lynis
    else
      LYNIS_CMD=/opt/lynis/lynis
    fi
  else
    # Explicit locations work when a service PATH omits /usr/sbin.
    for path in /usr/sbin/lynis /usr/bin/lynis /usr/local/bin/lynis /opt/lynis/lynis; do
      if [[ -f "$path" && -x "$path" ]]; then
        LYNIS_CMD="$path"
        break
      fi
    done
    if [[ -z "$LYNIS_CMD" ]]; then
      path="$(command -v lynis 2>/dev/null || true)"
      if [[ "$path" == /* && -f "$path" && -x "$path" ]]; then
        LYNIS_CMD="$path"
      fi
    fi
    [[ -n "$LYNIS_CMD" ]] && LYNIS_SOURCE="external"
  fi

  if [[ -n "$LYNIS_CMD" ]]; then
    LYNIS_INSTALLED=true
    LYNIS_VERSION="$(lynis_run show version 2>/dev/null || echo unknown)"
  fi
}


# ==========================================================
# Installation
# ==========================================================
install_lynis() {
  local FUNC_VERSION="1.0"
  pmx_journal_context "install_lynis" "$FUNC_VERSION"

  show_proxmenux_logo
  msg_title "$(translate "$SCRIPT_TITLE")"
  msg_info2 "$(translate "Installing latest Lynis security scan tool...")"

  # Install git if needed. Verify the install actually succeeded —
  # `apt-get install -y git >/dev/null 2>&1` followed by `msg_ok` would
  # otherwise lie about success and the next `git clone` would fail with
  # an opaque error. Audit Tier 6 — `lynis_installer.sh` apt silent.
  if ! command -v git >/dev/null 2>&1; then
    msg_info "$(translate "Installing Git as a prerequisite...")"
    apt-get update -qq >/dev/null 2>&1
    if pmx_install_pkg git && command -v git >/dev/null 2>&1; then
      msg_ok "$(translate "Git installed")"
    else
      msg_error "$(translate "Could not install Git — Lynis cannot be cloned. Run 'apt-get install git' manually.")"
      return 1
    fi
  fi

  # Reject unowned paths and symlinks before deleting or cloning files.
  if { [[ -e /opt/lynis || -L /opt/lynis ]] && ! lynis_git_checkout; } ||
     ! lynis_install_target_safe; then
    msg_error "$(translate "Existing Lynis files are not managed by ProxMenux. Refusing to overwrite them.")"
    return 1
  fi

  # Remove old installation if present
  if [[ -d /opt/lynis ]]; then
    msg_info "$(translate "Removing previous Lynis installation...")"
    pmx_record_execution "remove previous Lynis installation from /opt/lynis" "rm -rf /opt/lynis"
    rm -rf /opt/lynis >/dev/null 2>&1
    msg_ok "$(translate "Previous installation removed")"
  fi

  # Clone from GitHub
  msg_info "$(translate "Cloning Lynis from GitHub...")"
  pmx_record_execution "install Lynis in /opt/lynis" "git clone https://github.com/CISOfy/lynis.git /opt/lynis"
  if git clone --quiet https://github.com/CISOfy/lynis.git /opt/lynis >/dev/null 2>&1; then
    if ! printf 'proxmenux-lynis-git-v1\n' > /opt/lynis/.proxmenux-managed; then
      msg_error "$(translate "Could not record Lynis installation ownership.")"
      return 1
    fi
    # pmx_write_file follows symlinks; recheck just before writing.
    if ! lynis_install_target_safe; then
      msg_error "$(translate "Unsafe Lynis wrapper target. Refusing to overwrite it.")"
      return 1
    fi
    # Create wrapper script
    pmx_write_file /usr/local/bin/lynis << 'EOF'
#!/bin/bash
cd /opt/lynis && ./lynis "$@"
EOF
    chmod +x /usr/local/bin/lynis
    msg_ok "$(translate "Lynis installed successfully from GitHub")"
  else
    msg_error "$(translate "Failed to clone Lynis from GitHub")"
    return 1
  fi

  # Verify
  if /usr/local/bin/lynis show version >/dev/null 2>&1; then
    local version
    version=$(/usr/local/bin/lynis show version 2>/dev/null)
    update_component_status "lynis" "installed" "$version" "security" '{}'
    msg_ok "$(translate "Lynis version:") $version"
    msg_success "$(translate "Lynis is ready to use")"
  else
    msg_warn "$(translate "Lynis installation could not be verified")"
  fi

  msg_info2 "$(translate "You can run a security audit with:")"
  echo -e "  lynis audit system"
  echo ""
  msg_success "$(translate "Installation completed. Press Enter to continue...")"
  read -r
}


# ==========================================================
# Update
# ==========================================================
update_lynis() {
  local FUNC_VERSION="1.0"
  pmx_journal_context "update_lynis" "$FUNC_VERSION"

  show_proxmenux_logo
  msg_title "$(translate "$SCRIPT_TITLE")"
  msg_info2 "$(translate "Updating Lynis to the latest version...")"

  detect_lynis
  if [[ "$LYNIS_SOURCE" != "git" ]]; then
    msg_error "$(translate "This installation is externally managed. Use its package manager to update Lynis.")"
    return 1
  fi

  if [[ -d /opt/lynis/.git ]]; then
    cd /opt/lynis
    msg_info "$(translate "Pulling latest changes from GitHub...")"
    pmx_record_execution "update Lynis installation in /opt/lynis" "git pull --quiet"
    if git pull --quiet >/dev/null 2>&1; then
      local version
      version=$(lynis_run show version 2>/dev/null)
      update_component_status "lynis" "installed" "$version" "security" '{}'
      msg_ok "$(translate "Lynis updated to version:") $version"
    else
      msg_error "$(translate "Failed to update Lynis")"
    fi
  else
    msg_warn "$(translate "Lynis was not installed from Git. Reinstalling...")"
    install_lynis
    return
  fi

  msg_success "$(translate "Update completed. Press Enter to continue...")"
  read -r
}


# ==========================================================
# Run Audit
# ==========================================================
run_audit() {
  local FUNC_VERSION="1.0"
  pmx_journal_context "run_audit" "$FUNC_VERSION"

  show_proxmenux_logo
  msg_title "$(translate "$SCRIPT_TITLE")"
  msg_info2 "$(translate "Running Lynis security audit...")"
  echo ""

  if [[ -z "$LYNIS_CMD" ]]; then
    msg_error "$(translate "Lynis command not found")"
    return 1
  fi

  # Run the audit
  pmx_record_execution "run Lynis system audit" "$LYNIS_CMD audit system --no-colors"
  lynis_run audit system --no-colors 2>&1

  echo ""
  msg_success "$(translate "Audit completed. Press Enter to continue...")"
  read -r
}


# ==========================================================
# Uninstall
# ==========================================================
uninstall_lynis() {
  local FUNC_VERSION="1.0"
  pmx_journal_context "uninstall_lynis" "$FUNC_VERSION"

  show_proxmenux_logo
  msg_title "$(translate "$SCRIPT_TITLE")"
  msg_info2 "$(translate "Removing Lynis...")"

  detect_lynis
  if [[ "$LYNIS_SOURCE" != "git" ]] || ! lynis_git_checkout; then
    msg_error "$(translate "This installation is externally managed. Use its package manager to remove Lynis.")"
    return 1
  fi
  local remove_wrapper=false
  lynis_is_managed_wrapper && remove_wrapper=true
  pmx_record_execution "remove Lynis installation from /opt/lynis" "rm -rf /opt/lynis"
  rm -rf /opt/lynis 2>/dev/null
  if $remove_wrapper; then
    pmx_remove_file /usr/local/bin/lynis 2>/dev/null
  fi

  update_component_status "lynis" "removed" "" "security" '{}'

  msg_ok "$(translate "Lynis has been removed")"
  msg_success "$(translate "Uninstallation completed. Press Enter to continue...")"
  read -r
}


# ==========================================================
# Main
# ==========================================================
main() {
  detect_lynis

  if $LYNIS_INSTALLED; then
    # Already installed - show action menu
    local action_text
    action_text="\n$(translate 'Lynis is currently installed.')\n"
    action_text+="$(translate 'Version:') $LYNIS_VERSION\n\n"
    action_text+="$(translate 'What would you like to do?')"

    local ACTION
    if [[ "$LYNIS_SOURCE" == "git" ]]; then
      ACTION=$(hybrid_menu "$(translate 'Lynis Management')" "$action_text" 20 70 5 \
        "audit" "$(translate 'Run security audit now')" \
        "update" "$(translate 'Update Lynis to latest version')" \
        "reinstall" "$(translate 'Reinstall Lynis')" \
        "remove" "$(translate 'Uninstall Lynis')" \
        "cancel" "$(translate 'Cancel')" \
      ) || ACTION="cancel"
    else
      action_text+="\n$(translate 'Use your package manager to update or remove this Lynis installation.')"
      ACTION=$(hybrid_menu "$(translate 'Lynis Management')" "$action_text" 20 70 2 \
        "audit" "$(translate 'Run security audit now')" \
        "cancel" "$(translate 'Cancel')" \
      ) || ACTION="cancel"
    fi

    case "$ACTION" in
      audit)
        run_audit
        ;;
      update)
        update_lynis
        ;;
      reinstall)
        if hybrid_yesno "$(translate 'Reinstall Lynis')" \
          "\n\n$(translate 'This will remove and reinstall Lynis from the latest GitHub source. Continue?')" 12 70; then
          install_lynis
        fi
        ;;
      remove)
        if hybrid_yesno "$(translate 'Remove Lynis')" \
          "\n\n$(translate 'This will completely remove Lynis from the system. Continue?')" 12 70; then
          uninstall_lynis
        fi
        ;;
      cancel|*)
        exit 0
        ;;
    esac
  else
    # Not installed - confirm and install
    local info_text
    info_text="\n$(translate 'Lynis is not installed on this system.')\n\n"
    info_text+="$(translate 'Lynis is a security auditing tool that performs comprehensive system scans including:')\n\n"
    info_text+="  - $(translate 'System hardening scoring (0-100)')\n"
    info_text+="  - $(translate 'Vulnerability detection')\n"
    info_text+="  - $(translate 'Configuration analysis')\n"
    info_text+="  - $(translate 'Compliance checking (PCI-DSS, HIPAA, etc.)')\n\n"
    info_text+="$(translate 'It will be installed from the official GitHub repository.')\n\n"
    info_text+="$(translate 'Do you want to proceed?')"

    if hybrid_yesno "$(translate 'Install Lynis')" "$info_text" 22 70; then
      install_lynis
    else
      exit 0
    fi
  fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main
fi
