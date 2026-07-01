from __future__ import annotations

from models import L2vpnLink, PingResult


class JunosPinger:
    def __init__(self, dev) -> None:
        self.dev = dev

    def ping_link(self, link: L2vpnLink, count: int = 100) -> PingResult:
        loss = self.ping_loss(
            dest_ip=link.remote_ip,
            source_ip=link.local_ip,
            count=count,
        )
        return PingResult(
            interface=link.interface,
            description=link.description,
            local_ip=link.local_ip,
            remote_ip=link.remote_ip,
            loss=loss,
        )

    def ping_loss(self, dest_ip: str, source_ip: str, count: int = 100) -> int | None:
        from jnpr.junos.exception import RpcError, RpcTimeoutError
        try:
            resp = self.dev.rpc.ping(
                host=dest_ip,
                source=source_ip,
                count=str(count),
                rapid=True,
            )
        except RpcTimeoutError:
            # Пинг не уложился в таймаут: адресат не отвечает — это полный обрыв
            # канала (100% потерь), а не ошибка. Иначе такой случай уходил бы в
            # ERROR и сообщение не отправлялось.
            return count
        except RpcError as exc:
            raise RuntimeError(f"Ошибка ping {dest_ip} (source {source_ip}): {exc}") from exc
        return self._parse_loss(resp)

    @staticmethod
    def _parse_loss(xml_root) -> int | None:
        for el in xml_root.iter():
            tag = el.tag
            if isinstance(tag, str) and "}" in tag:
                el.tag = tag.split("}", 1)[1]

        summ = xml_root.find(".//probe-results-summary")
        if summ is None:
            return None

        def _t(tag: str) -> str:
            val = summ.findtext(tag)
            return val.strip() if val else ""

        sent = _t("probes-sent")        or _t("packets-transmitted")
        recv = _t("responses-received") or _t("packets-received")

        if sent and recv:
            return int(sent) - int(recv)

        loss_pct = _t("packet-loss")
        return int(loss_pct) if loss_pct else None
