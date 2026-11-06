import http.client
import threading
from http.server import HTTPServer

from mirage import dashboard as dashboard_module


def test_dashboard_rejects_query_token_and_accepts_bearer_header(monkeypatch):
    monkeypatch.setattr(dashboard_module, "_token", lambda: "test-secret")
    dashboard = dashboard_module.Dashboard(port=0)
    dashboard._page = lambda: b"dashboard-ok"
    server = HTTPServer(("127.0.0.1", 0), dashboard._handler())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)

        connection.request("GET", "/?token=test-secret")
        query_response = connection.getresponse()
        assert query_response.status == 401
        query_response.read()

        connection.request(
            "GET",
            "/",
            headers={"Authorization": "Bearer test-secret"},
        )
        header_response = connection.getresponse()
        assert header_response.status == 200
        assert header_response.read() == b"dashboard-ok"
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
