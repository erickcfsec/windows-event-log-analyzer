
"""
Windows Event Log Analyzer
Module: collector.py

Responsible for retrieving Windows Security events
and returning their original XML representation.
"""

from typing import Iterable, Optional

import pywintypes
import win32evtlog


class EventLogCollectionError(Exception):
    """Raised when Windows Event Log collection fails."""


class EventLogCollector:
    """Collects raw events from a Windows Event Log channel."""

    def __init__(
        self,
        channel: str = "Security",
        batch_size: int = 32
    ):
        if not isinstance(channel, str) or not channel.strip():
            raise ValueError("Channel must be a non-empty string.")

        if (
            isinstance(batch_size, bool)
            or not isinstance(batch_size, int)
            or batch_size < 1
        ):
            raise ValueError("Batch size must be a positive integer.")

        self.channel = channel
        self.batch_size = batch_size

    @staticmethod
    def _build_query(
        event_ids: Optional[Iterable[int]] = None
    ) -> str:
        """Builds an XPath query for the requested Event IDs."""

        if event_ids is None:
            return "*"

        ids = list(event_ids)

        if not ids:
            raise ValueError("Event IDs cannot be an empty list.")

        for event_id in ids:
            if (
                isinstance(event_id, bool)
                or not isinstance(event_id, int)
                or event_id <= 0
            ):
                raise ValueError(
                    "Every Event ID must be a positive integer."
                )

        ids = sorted(set(ids))

        conditions = " or ".join(
            f"EventID={event_id}" for event_id in ids
        )

        return f"*[System[({conditions})]]"

    def collect(
        self,
        event_ids: Optional[Iterable[int]] = None,
        max_events: int = 100
    ) -> list[str]:
        """
        Retrieves the most recent events.

        Returns a list of raw XML event strings.
        """

        if (
            isinstance(max_events, bool)
            or not isinstance(max_events, int)
            or max_events < 1
        ):
            raise ValueError("max_events must be a positive integer.")

        query = self._build_query(event_ids)

        flags = (
            win32evtlog.EvtQueryChannelPath
            | win32evtlog.EvtQueryReverseDirection
        )

        query_handle = None
        collected_events = []

        try:
            query_handle = win32evtlog.EvtQuery(
                self.channel,
                flags,
                query
            )

            while len(collected_events) < max_events:

                remaining = max_events - len(collected_events)

                current_batch_size = min(
                    self.batch_size,
                    remaining
                )

                event_handles = win32evtlog.EvtNext(
                    query_handle,
                    current_batch_size
                )

                if not event_handles:
                    break

                for event_handle in event_handles:

                    event_xml = win32evtlog.EvtRender(
                        event_handle,
                        win32evtlog.EvtRenderEventXml
                    )

                    collected_events.append(event_xml)

                # PyEVT_HANDLE objects close themselves when
                # their Python references are released.
                del event_handles

            return collected_events

        except pywintypes.error as exc:
            raise EventLogCollectionError(
                f"Unable to collect events from channel "
                f"'{self.channel}'. Check permissions and "
                f"channel availability. Windows error: {exc}"
            ) from exc

        finally:
            # The PyEVT_HANDLE wrapper automatically calls
            # the native EvtClose function when destroyed.
            query_handle = None
