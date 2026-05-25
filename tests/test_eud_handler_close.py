"""Regression tests for EudHandler.close_connection.

A pilot's client (ATAK) can drop the socket before RabbitMQ setup completes —
e.g. during the TLS handshake on the SSL streaming port, or a bare TCP probe.
When that happens `self.rabbit_channel` is still ``None`` (setup_rabbitmq either
never ran or hit its ``except`` and returned early). close_connection used to
call ``self.rabbit_channel.basic_publish(...)`` unconditionally, raising
``AttributeError: 'NoneType' object has no attribute 'basic_publish'`` and
killing the handler thread on *every* such connection — which flooded the log
and made the streaming listener look dead. close_connection must be a safe
no-op on the RabbitMQ leg when there is no channel.
"""

import logging
from socket import SHUT_RDWR

from opentakserver.eud_handler.EudHandler import EudHandler


class _FakeRequest:
    """Stand-in for the client socket so close_connection can shut it down."""

    def __init__(self):
        self.shutdown_called_with = None
        self.close_called = False

    def shutdown(self, how):
        self.shutdown_called_with = how

    def close(self):
        self.close_called = True


def _make_handler(rabbit_channel):
    # Bypass __init__ — the real one is a socketserver handler that runs handle()
    # against a live socket. We only want to exercise close_connection in isolation.
    handler = EudHandler.__new__(EudHandler)
    handler.logger = logging.getLogger("test-eud-handler")
    handler.client_address = ("203.0.113.5", 4242)
    handler.rabbit_channel = rabbit_channel
    handler.uid = None
    handler.user = None
    handler.shutdown = False
    handler.request = _FakeRequest()
    # unbind_rabbitmq_queues also touches the channel; stub it for this unit test.
    handler.unbind_rabbitmq_queues = lambda: None
    return handler


def test_close_connection_with_no_rabbit_channel_does_not_raise():
    """The regression: close_connection on a channel-less connection must not raise."""
    handler = _make_handler(rabbit_channel=None)

    handler.close_connection()  # must NOT raise AttributeError

    # And it must still tear the socket down cleanly.
    assert handler.shutdown is True
    assert handler.request.shutdown_called_with == SHUT_RDWR
    assert handler.request.close_called is True
