"""Regression tests: XSS in the public /acme/terms page.

The server-side renderer escaped only ``& < >`` before interpolating
autolinked URLs into a double-quoted ``href`` attribute, and its URL
character class admitted ``"`` — the same missing-quote-escape flaw the
admin ToS preview had (PR #247). A quote inside a stored ToS URL therefore
broke out of the attribute and injected arbitrary attributes (for example
``onmouseover``) into an unauthenticated, public page.

The body is admin-supplied via the ACME settings, so this is defence in
depth against a hostile or compromised operator account, mirroring the
frontend fix.
"""
import json
from html.parser import HTMLParser

import pytest


TOS_KEY = 'acme.terms_of_service'


class _AttrCollector(HTMLParser):
    """Collect every (tag, attribute-name) pair in a document."""

    def __init__(self):
        super().__init__()
        self.attrs = []

    def handle_starttag(self, tag, attrs):
        for name, _ in attrs:
            self.attrs.append((tag, name.lower()))


def _set_tos(app, body, title='Terms'):
    from models import db, SystemConfig
    with app.app_context():
        row = SystemConfig.query.filter_by(key=TOS_KEY).first()
        value = json.dumps({'title': title, 'body': body})
        if row:
            row.value = value
        else:
            db.session.add(SystemConfig(key=TOS_KEY, value=value))
        db.session.commit()


@pytest.fixture(autouse=True)
def _clean_tos(app):
    yield
    from models import db, SystemConfig
    with app.app_context():
        SystemConfig.query.filter_by(key=TOS_KEY).delete()
        db.session.commit()


def _page_attrs(client):
    r = client.get('/acme/terms')
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    parser = _AttrCollector()
    parser.feed(html)
    return html, parser.attrs


def test_quote_in_url_cannot_break_out_of_href(app, client):
    _set_tos(app, 'Read https://a"onmouseover=alert(1)//x first')
    html, attrs = _page_attrs(client)
    # No element anywhere in the page may carry an event-handler attribute.
    for tag, name in attrs:
        assert not name.startswith('on'), f'injected attribute {name} on <{tag}>'
    # The quote survives only in escaped form.
    assert '&quot;' in html


def test_quote_in_plain_text_is_escaped(app, client):
    _set_tos(app, 'A "quoted" sentence with no URL.')
    html, attrs = _page_attrs(client)
    for tag, name in attrs:
        assert not name.startswith('on'), f'injected attribute {name} on <{tag}>'
    assert '&quot;quoted&quot;' in html


def test_html_in_body_stays_inert(app, client):
    _set_tos(app, '<img src=x onerror=alert(1)> and <script>alert(2)</script>')
    html, attrs = _page_attrs(client)
    tags = {tag for tag, _ in attrs}
    assert 'img' not in tags
    assert '<script>alert' not in html
    assert '&lt;script&gt;' in html


def test_legitimate_url_still_autolinks(app, client):
    _set_tos(app, 'See https://example.com/tos for details.\n\nSecond paragraph.')
    html, _ = _page_attrs(client)
    assert '<a href="https://example.com/tos"' in html
    assert 'rel="noopener"' in html
    # Paragraph split still works.
    assert html.count('<p>') == 2
