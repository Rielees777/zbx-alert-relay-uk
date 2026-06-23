from __future__ import annotations

import ipaddress

from models import L2vpnLink


class JunosInterfaceParser:
    def __init__(self, xml_root) -> None:
        self.root = self._strip_ns(xml_root)

    @classmethod
    def from_device(cls, dev, detail: bool = True) -> "JunosInterfaceParser":
        return cls(dev.rpc.get_interface_information(detail=detail))

    def l2vpn_links(
        self,
        cod_name: str,
        want:     str = "l2vpn",
        family:   str = "inet",
    ) -> list[L2vpnLink]:
        cod_l  = (cod_name or "").lower()
        want_l = (want     or "").lower()
        links: list[L2vpnLink] = []

        for phys in self.root.findall("physical-interface"):
            phys_name = self._text(phys, "name")
            phys_desc = self._text(phys, "description")

            for log in phys.findall("logical-interface"):
                name = self._text(log, "name") or phys_name
                desc = self._text(log, "description") or phys_desc
                d    = desc.lower()

                if not (cod_l and cod_l in d and want_l in d):
                    continue

                for af in log.findall("address-family"):
                    if self._text(af, "address-family-name") != family:
                        continue
                    for addr in af.findall("interface-address"):
                        local = self._text(addr, "ifa-local")
                        if not local:
                            continue
                        links.append(
                            L2vpnLink(
                                interface=name,
                                description=desc,
                                local_ip=local,
                                remote_ip=self._remote_ip(local),
                            )
                        )
        return links

    @staticmethod
    def _remote_ip(local_str: str) -> str:
        net   = ipaddress.ip_network(f"{local_str}/30", strict=False)
        local = ipaddress.ip_address(local_str)
        return str(next(h for h in net.hosts() if h != local))

    @staticmethod
    def _strip_ns(root):
        for el in root.iter():
            tag = el.tag
            if isinstance(tag, str) and "}" in tag:
                el.tag = tag.split("}", 1)[1]
        return root

    @staticmethod
    def _text(node, tag: str) -> str:
        val = node.findtext(tag)
        return val.strip() if val else ""
