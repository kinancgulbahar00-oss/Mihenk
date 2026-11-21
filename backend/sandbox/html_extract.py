"""HTML belgesinden oltalama icin anlamli ozelliklerin cikarilmasi (E-01, E-07, E-10, E-12).

Belge, tarayicilarin uyguladigi WHATWG agac kurma algoritmasiyla (Lexbor; selectolax) ayristirilir ve
bilgiler belirtec akisindan degil KURULAN AGACTAN okunur. Onceki surumlerde Python'un HTMLParser sinifi
uzerine elle yazilmis durum makinesi (ham metin ogeleri, yabanci icerikten cikis, tumlesme noktalari)
her turda yeni bir fark uretiyordu ve davranisi Python yama surumune gore degisiyordu.

`scripting=True`: JavaScript acik bir tarayici gibi; <noscript> icerigi tek bir metin dugumudur.

Bu modul yalnizca standart kitapligi ve selectolax'i kullanir; isci surecte calisir
(backend/sandbox/pool.py). Saldirganin denetimindeki girdiyi isler: sonuc her zaman boyutu sinirli,
duz veri (dict/list/str/int/bool) olmalidir.
"""

import re

from selectolax.lexbor import LexborHTMLParser

# Agac gezintisinde islenen en fazla dugum; asilirsa sonuc `truncated_tree` isareti tasir
MAX_NODES = 250_000
MAX_TEXT_CHUNKS = 4000
MAX_LINKS = 500
MAX_INPUTS = 300
MAX_FRAMES = 20
MAX_SRCDOC = 1_000_000

# Satir ici ogeler metni BOLMEZ (A-03): 'Gar<b></b>anti' tarayicida 'Garanti' olarak gorunur.
INLINE = frozenset({"a", "abbr", "acronym", "b", "bdi", "bdo", "big", "cite", "code", "del", "dfn", "em", "font",
                    "i", "ins", "kbd", "label", "mark", "nobr", "q", "s", "samp", "small", "span", "strike",
                    "strong", "sub", "sup", "tt", "u", "var", "wbr", "img", "input", "select", "button",
                    "script", "style", "noscript", "template", "meta", "link", "base", "area", "map"})
VOID = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track",
                  "wbr", "param"})
# Icerigi sayfa metni olarak cizilmeyen ogeler
# <object> burada YOKTUR: kaynagi yuklenemeyen (ya da hic olmayan) nesnenin yedek icerigi sayfada cizilir.
NO_TEXT = frozenset({"script", "style", "noscript", "template", "iframe", "noembed", "noframes",
                     "head", "datalist"})
EMBEDS = frozenset({"iframe", "frame", "object", "embed"})
EXEC_SCRIPT_TYPES = frozenset({"", "module", "text/javascript", "application/javascript", "text/ecmascript",
                               "application/ecmascript", "application/x-javascript", "text/jscript",
                               "text/livescript", "text/javascript1.5", "importmap", "speculationrules"})
SVG_INTEGRATION = frozenset({"foreignobject", "desc", "title"})
MATH_TEXT_INTEGRATION = frozenset({"mi", "mo", "mn", "ms", "mtext"})
IDENTITY_META = frozenset({"og:site_name", "og:title", "application-name"})

_WS_RE = re.compile(r"\s+")
_NON_ALNUM_RE = re.compile(r"[^A-Za-z0-9]+")
_CHARSET_IN_CONTENT_RE = re.compile(r"charset\s*=\s*[\"']?\s*([A-Za-z0-9._:-]+)", re.IGNORECASE)
# CSS 'content' dizgileri: metin HTML'de hic olmadan ::before/::after ile yazilabilir (E-07)
_CSS_CONTENT_RE = re.compile(r"content\s*:\s*((?:\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|\s+)+)", re.IGNORECASE | re.DOTALL)
_CSS_STRING_RE = re.compile(r"\"((?:[^\"\\]|\\.)*)\"|'((?:[^'\\]|\\.)*)'", re.DOTALL)
_CSS_ESCAPE_RE = re.compile(r"\\([0-9a-fA-F]{1,6})[ \t\n\r\f]?|\\(.)", re.DOTALL)
# Parola maskesi satir ici stil yerine <style> kuraliyla da verilebilir: type=text alani parola gibi cizilir
_CSS_MASK_RE = re.compile(r"-webkit-text-security\s*:\s*(?!none)[a-z]", re.IGNORECASE)
# content: attr(data-x) -> metin HTML'de oznitelikte durur, CSS ile cizilir
_CSS_ATTR_RE = re.compile(r"content\s*:[^;}]*attr\(", re.IGNORECASE)
_ZERO_RE = re.compile(r"^[+-]?0*(?:\.0*)?(?:[a-z%]*)$")
# XML belgesinde '/>' her ogeyi kapatir; HTML ayristiricisi bos olmayan ogelerde bunu yok sayar
# Logo / baslik benzeri oge (G-10): kurum adinin GECTIGI YER bilgi tasir
_PROMINENT_ATTR_RE = re.compile(r"logo|brand|marka|header|baslik|banner|kurum", re.IGNORECASE)
PROMINENT_TAGS = frozenset({"h1", "h2", "h3"})
# Isci yanitinin toplam metin boyutu (G-13): ana surecle ileti siniri asilmasin
MAX_TEXT_CHARS = 600_000
_XML_SELF_CLOSING_RE = re.compile(r"<([A-Za-z_][\w:.\-]*)((?:[^<>\"']|\"[^\"]*\"|'[^']*')*?)/>")


def _css_unescape(value):
    def repl(m):
        if m.group(1):
            try:
                code = int(m.group(1), 16)
                return chr(code) if 0 < code < 0x110000 and not 0xD800 <= code <= 0xDFFF else "�"
            except ValueError:
                return ""
        return "" if m.group(2) in "\n\r\f" else m.group(2)

    return _CSS_ESCAPE_RE.sub(repl, value)


def css_content_strings(css):
    """Stil sayfasindaki `content: "..."` dizgileri (CSS kacislari cozulmus)."""
    out = []
    for m in _CSS_CONTENT_RE.finditer(css[:200_000]):
        parts = [_css_unescape(a or b or "") for a, b in _CSS_STRING_RE.findall(m.group(1))]
        text = "".join(parts).strip()
        if text:
            out.append(text[:300])
        if len(out) >= 50:
            break
    return out


def _declarations(style):
    """Satir ici stil bildirimleri: {ozellik: deger}. Tarayici gibi ozellik adi TAM eslesir, ayni ozelligin
    SON bildirimi gecerlidir (!important olan one gecer); ozel ozellikler (--x) ve gecersiz adlar atilir.
    Dizgi aramasi ('display:none' geciyor mu) gorunur metni gizli saydiriyordu (E-07)."""
    decls = {}
    important = set()
    depth = 0
    quote = None
    start = 0
    parts = []
    for i, ch in enumerate(style):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")" and depth:
            depth -= 1
        elif ch == ";" and not depth:
            parts.append(style[start:i])
            start = i + 1
    parts.append(style[start:])
    for part in parts:
        name, sep, value = part.partition(":")
        name = name.strip().lower()
        if not sep or not name or name.startswith("--") or not re.fullmatch(r"-?[a-z][a-z0-9-]*", name):
            continue
        value = value.strip().lower()
        is_important = value.endswith("!important") or bool(re.search(r"!\s*important\s*$", value))
        if is_important:
            value = re.sub(r"!\s*important\s*$", "", value).strip()
        if not value or (name in important and not is_important):
            continue
        decls[name] = value
        if is_important:
            important.add(name)
    return decls


def _basename_words(url):
    return _NON_ALNUM_RE.sub(" ", (url or "").rsplit("/", 1)[-1])


class _Collector:
    def __init__(self, xml):
        self.xml = xml
        self.title = None
        self.h1_all = None
        self.h1_visible = None
        self.meta_identity = []
        self.logos = []
        self.inputs = []
        self.labels = []
        self.captions = []
        self.form_actions = []
        self.formactions = []
        self.links = []
        self.frames = []
        self.empty_frames = 0
        self.srcdocs = []
        self.meta_refresh = []
        self.inert_refresh = []
        self.base_href = None
        self.meta_charsets = []
        self.css_text = []
        self.exec_scripts = 0
        self.scripts = 0
        self.event_handlers = False
        self.buttons = 0
        self.text_inputs = 0
        self.password_inputs = 0
        self.all_inputs = 0
        self.stylesheets = False
        self.style_elements = False
        self.images = False
        self.hidden_hits = False
        self.masked_inputs = False
        self.text_all = []
        self.text_visible = []
        # Gorunen oznitelik metni (G-06): girdi degeri, yer tutucu, dugme degeri, aria-label, alt
        self.attr_text = []
        # Logo / baslik benzeri ogelerdeki metin (G-10)
        self.prominent = []
        # Metnin ekrandaki sirasini degistiren yapi var mi? (G-04): <bdo>, dir=rtl, unicode-bidi, float, order
        self.reordered = False
        self.referrer_policy = None
        self.get_forms = []
        # Veri toplayan form: method=post (tarayicida girilen metin sunucuya gonderilir)
        self.post_forms = 0
        # Serbest metin alan sayisi (<select> haric) ve sayfanin alt kaynaklari (stil sayfasi, gorsel)
        self.free_inputs = 0
        self.stylesheet_urls = []
        self.image_urls = []
        self.css_masked = False
        self.css_attr = False
        self.data_text = []
        self.chars = 0
        self._buf_all = []
        self._buf_vis = []
        self._last_chunk = ""
        self._label_refs = []
        self._ids = {}
        self.nodes = 0
        self.truncated_tree = False

    # --- metin ---------------------------------------------------------------------------
    def flush(self):
        if self._buf_all:
            chunk = _WS_RE.sub(" ", "".join(self._buf_all)).strip()
            self._buf_all = []
            if chunk:
                self._last_chunk = chunk
                if len(self.text_all) < MAX_TEXT_CHUNKS and self.chars < MAX_TEXT_CHARS:
                    self.text_all.append(chunk)
                    self.chars += len(chunk)
        if self._buf_vis:
            chunk = _WS_RE.sub(" ", "".join(self._buf_vis)).strip()
            self._buf_vis = []
            if chunk and len(self.text_visible) < MAX_TEXT_CHUNKS and self.chars < MAX_TEXT_CHARS:
                self.text_visible.append(chunk)
                self.chars += len(chunk)

    def attr(self, value):
        value = _WS_RE.sub(" ", value or "").strip()
        if value and len(self.attr_text) < 200:
            self.attr_text.append(value[:200])

    def caption(self):
        """Girdiden hemen onceki metin (E-10): aciklama <label> yerine <div>, <span> ya da tablo hucresinde
        yazilabilir. Bekleyen satir ici metin, yoksa en son kapanan metin parcasi; bir kez kullanilir."""
        pending = _WS_RE.sub(" ", "".join(self._buf_all)).strip()
        text = pending or self._last_chunk
        self._last_chunk = ""
        return text[-80:] if text and len(text) <= 160 else ""


def _text_of(node, limit=200):
    """Bir ogenin alt agacindaki metin (ozyinelemesiz, sinirli)."""
    out = []
    size = 0
    stack = [node]
    seen = 0
    while stack and size < limit and seen < 2000:
        cur = stack.pop()
        seen += 1
        tag = cur.tag
        if tag == "-text":
            value = cur.text_content or ""
            out.append(value)
            size += len(value)
            continue
        child = cur.last_child
        while child is not None:
            stack.append(child)
            child = child.prev
    return _WS_RE.sub(" ", "".join(out)).strip()[:limit]


def _prepare_xml(text):
    def repl(m):
        name = m.group(1)
        if name.rsplit(":", 1)[-1].lower() in VOID:
            return m.group(0)
        return f"<{name}{m.group(2)}></{name}>"

    return _XML_SELF_CLOSING_RE.sub(repl, text)


def extract(html, xml=False):
    """Belgeyi agac kurucusuyla ayristirir ve duz veri olarak ozelliklerini dondurur."""
    if xml:
        html = _prepare_xml(html)
    tree = LexborHTMLParser(html, scripting=True)
    c = _Collector(xml)
    root = tree.root
    if root is not None:
        _walk(root, c)
    c.flush()

    if isinstance(c.title, list):
        c.title = "".join(c.title)
    if isinstance(c.h1_all, list):
        c.h1_all, c.h1_visible = "".join(c.h1_all), "".join(c.h1_visible)
    for index, ref in c._label_refs[:50]:
        texts = [_text_of(c._ids[i], 120) for i in ref.split()[:4] if i in c._ids]
        if texts and index < len(c.inputs):
            c.inputs[index] += " " + " ".join(texts)[:200].lower()

    return {
        "title": c.title,
        "h1": c.h1_all,
        "h1_visible": c.h1_visible,
        "meta_identity": c.meta_identity[:10],
        "logos": [x for x in c.logos if x and x.strip()][:80],
        "inputs": c.inputs,
        "labels": c.labels[:200],
        "captions": c.captions[:200],
        "form_actions": c.form_actions[:50],
        "formactions": c.formactions[:50],
        "links": c.links,
        "frames": c.frames,
        "empty_frames": c.empty_frames,
        "srcdocs": c.srcdocs,
        "meta_refresh": c.meta_refresh[:5],
        "inert_refresh": c.inert_refresh[:5],
        "base_href": c.base_href,
        "meta_charsets": c.meta_charsets[:5],
        "css_text": c.css_text[:50],
        "exec_scripts": c.exec_scripts,
        "scripts": c.scripts,
        "event_handlers": c.event_handlers,
        "buttons": c.buttons,
        "text_inputs": c.text_inputs,
        "password_inputs": c.password_inputs,
        "all_inputs": c.all_inputs,
        "stylesheets": c.stylesheets,
        "style_elements": c.style_elements,
        "images": c.images,
        "hidden_hits": c.hidden_hits,
        "masked_inputs": c.masked_inputs,
        "text": c.text_all,
        "text_visible": c.text_visible,
        "attr_text": c.attr_text,
        "prominent": c.prominent[:200],
        "reordered": c.reordered,
        "referrer_policy": c.referrer_policy,
        "get_forms": c.get_forms[:20],
        "post_forms": c.post_forms,
        "free_inputs": c.free_inputs,
        "stylesheet_urls": c.stylesheet_urls[:3],
        "image_urls": c.image_urls[:3],
        "css_masked": c.css_masked,
        "css_attr": c.css_attr,
        "data_text": c.data_text[:100] if c.css_attr else [],
        "truncated_tree": c.truncated_tree or c.chars >= MAX_TEXT_CHARS,
    }


# Gezinti durumu: (yabanci, gizli, gorunurluk_gizli, yazi_boyu_sifir, metin_yok, etkisiz, baglanti, etiket, h1, one_cikan)
def _walk(root, c):
    # Yigin ogeleri: (dugum, durum) ya da cikis isareti (None, (etiket, ...))
    base_state = (0, False, False, False, False, False, None, None, False, False)
    stack = [(root, base_state)]
    while stack:
        node, state = stack.pop()
        if node is None:
            _leave(state, c)
            continue
        c.nodes += 1
        if c.nodes > MAX_NODES:
            c.truncated_tree = True
            return
        tag = node.tag
        if tag == "-text":
            _text(node, state, c)
            continue
        if not tag or tag[0] == "-":
            continue  # yorum, belge turu, belge dugumu
        child_state, exit_info, extra_children = _enter(node, tag, state, c)
        if exit_info is not None:
            stack.append((None, exit_info))
        if extra_children:
            for extra, extra_state in reversed(extra_children):
                child = extra.last_child
                while child is not None:
                    stack.append((child, extra_state))
                    child = child.prev
        child = node.last_child
        while child is not None:
            stack.append((child, child_state))
            child = child.prev


def _text(node, state, c):
    value = node.text_content
    if not value:
        return
    foreign, hid, vis, fs0, no_text, inert, link, label, h1, prom = state
    if no_text == "title":
        if c.title is None or isinstance(c.title, list):
            c.title = (c.title or []) + [value]
        return
    if no_text == "svg-title":
        c.logos.append(value[:200])
        return
    if no_text:
        return
    hidden = hid or vis or fs0 or inert
    c._buf_all.append(value)
    if not hidden:
        c._buf_vis.append(value)
    if h1:
        c.h1_all.append(value)
        if not hidden:
            c.h1_visible.append(value)
    if label is not None and len(c.labels[label]) < 200:
        c.labels[label] += value
    if link is not None and len(c.links[link][1]) < 200:
        c.links[link][1] += value
    if prom and len(c.prominent) < 200:
        c.prominent.append(value[:200])


def _leave(info, c):
    kind = info[0]
    if kind == "block":
        c.flush()
    elif kind == "title":
        if isinstance(c.title, list):
            c.title = "".join(c.title)
        elif c.title is None:
            c.title = ""
    elif kind == "h1":
        c.flush()
        c.h1_all = "".join(c.h1_all)
        c.h1_visible = "".join(c.h1_visible)
    if len(info) > 1 and info[1]:
        c.flush()


def _enter(node, raw_tag, state, c):
    foreign, hid, vis, fs0, no_text, inert, link, label, h1, prom = state
    tag = raw_tag.lower()
    if c.xml and ":" in tag:
        # Ad alani oneki (B-01): XHTML/SVG belgesindeki <html:form>, <xhtml:input> HTML ogesidir
        tag = tag.rsplit(":", 1)[-1]
    attrs = node.attributes or {}
    if c.xml:
        a = {}
        for k, v in attrs.items():
            a.setdefault((k or "").rsplit(":", 1)[-1].lower(), v or "")
    else:
        a = {(k or "").lower(): (v or "") for k, v in attrs.items()}
    block = tag not in INLINE
    if block:
        c.flush()
    exit_kind = "block" if block else None
    extra_children = None

    # --- ad alani: SVG/MathML icindeki oge HTML ogesi degildir; tumlesme noktalari HTML'e doner ---
    child_foreign = foreign
    if tag == "svg":
        child_foreign = 1
    elif tag == "math":
        child_foreign = 2
    elif foreign == 1 and tag in SVG_INTEGRATION:
        child_foreign = 0
    elif foreign == 2 and (tag in MATH_TEXT_INTEGRATION or (
            tag == "annotation-xml" and a.get("encoding", "").strip().lower() in ("text/html", "application/xhtml+xml"))):
        child_foreign = 0

    # --- gorunurluk sezgisi (yalnizca esikler icin; tespit gizli sayilan metni de kullanir: E-07) ---
    style = a.get("style", "")
    decls = _declarations(style) if style else {}
    if "hidden" in a and decls.get("display", "none") == "none":
        hid = True
        c.hidden_hits = True
    display = decls.get("display")
    if display == "none":
        hid = True
        c.hidden_hits = True
    opacity = decls.get("opacity")
    if opacity is not None and _ZERO_RE.match(opacity):
        hid = True
        c.hidden_hits = True
    visibility = decls.get("visibility")
    if visibility in ("hidden", "collapse"):
        vis = True
        c.hidden_hits = True
    elif visibility == "visible":
        vis = False
    size = decls.get("font-size")
    if size is not None:
        fs0 = bool(_ZERO_RE.match(size))
        if fs0:
            c.hidden_hits = True
    if decls and any(k in decls for k in ("clip", "clip-path", "text-indent", "position", "transform", "color",
                                          "height", "width", "max-height", "overflow", "z-index", "filter")):
        # Metni ekrandan cikarmanin dizgi aramasiyla izlenemeyen yollari: gizleme olasiligi olarak isaretlenir
        c.hidden_hits = True

    # Metnin ekrandaki sirasini degistiren yapilar (G-04): metin belgede ters, ekranda duz yazilabilir
    if tag == "bdo" or a.get("dir", "").strip().lower() == "rtl" or (decls and (
            decls.get("unicode-bidi", "") not in ("", "normal", "embed", "isolate")
            or decls.get("direction") == "rtl" or decls.get("float") in ("right", "inline-end")
            or "order" in decls or "reverse" in decls.get("flex-direction", "") or "reverse" in decls.get("flex-flow", "")
            or "scalex(-" in decls.get("transform", "").replace(" ", ""))):
        c.reordered = True
    if tag in PROMINENT_TAGS or _PROMINENT_ATTR_RE.search(a.get("class", "") + " " + a.get("id", "")):
        prom = True
    if a.get("aria-label"):
        c.attr(a["aria-label"])
    if len(c.data_text) < 100:
        for key, value in a.items():
            if key.startswith("data-") and value and 2 < len(value) <= 200:
                c.data_text.append(value)
    if "formmethod" in a and a.get("formmethod", "").strip().lower() == "post":
        c.post_forms += 1

    if any(k.startswith("on") and len(k) > 2 for k in a) or \
            a.get("href", "").strip().lower().startswith("javascript:"):
        c.event_handlers = True
    ident = a.get("id")
    if ident and len(c._ids) < 2000 and ident not in c._ids:
        c._ids[ident] = node  # metin yalnizca aria-labelledby ile anilirsa okunur

    child_no_text = no_text
    child_link, child_label, child_h1 = link, label, h1

    if tag == "title":
        if foreign == 1:
            child_no_text = "svg-title"  # SVG logolarin <title> etiketi sayfa basligi degil, logo etiketidir
        elif foreign == 0 and c.title is None and not inert:
            c.title = []
            child_no_text = "title"
            exit_kind = "title"
        else:
            child_no_text = True
    elif tag in NO_TEXT and not (foreign and tag not in ("script", "style")):
        child_no_text = True

    if tag == "h1" and c.h1_all is None and not inert and foreign == 0:
        c.h1_all, c.h1_visible = [], []
        child_h1 = True
        exit_kind = "h1"

    if tag == "script":
        c.scripts += 1
        if a.get("type", "").strip().lower().split(";")[0] in EXEC_SCRIPT_TYPES:
            c.exec_scripts += 1
    elif tag == "style":
        c.style_elements = True
        css = _text_of(node, 200_000)
        c.css_text.extend(css_content_strings(css))
        if _CSS_MASK_RE.search(css):
            c.css_masked = True
        if _CSS_ATTR_RE.search(css):
            c.css_attr = True
    elif tag == "link":
        rel = a.get("rel", "").lower()
        if "stylesheet" in rel:
            c.stylesheets = True
            if a.get("href", "").strip() and len(c.stylesheet_urls) < 3:
                c.stylesheet_urls.append(a["href"].strip()[:2100])
        if "icon" in rel:
            c.logos.append(_basename_words(a.get("href", "")))
    elif tag == "meta":
        key = a.get("property", a.get("name", "")).strip().lower()
        if key in IDENTITY_META:
            c.meta_identity.append(a.get("content", "")[:300])
        if "charset" in a:
            c.meta_charsets.append(a.get("charset", "").strip()[:60])
        elif a.get("http-equiv", "").strip().lower() == "content-type":
            m = _CHARSET_IN_CONTENT_RE.search(a.get("content", ""))
            if m:
                c.meta_charsets.append(m.group(1)[:60])
        if key == "referrer" and a.get("content", "").strip():
            c.referrer_policy = a.get("content", "").strip().lower()[:60]
        # Tarayici http-equiv degerini kirpmadan karsilastirir: ' refresh ' yonlendirme DEGILDIR (G-13)
        if a.get("http-equiv", "").lower() == "refresh" and foreign == 0:
            (c.inert_refresh if inert else c.meta_refresh).append(a.get("content", "")[:2100])
    elif tag == "base":
        if c.base_href is None and "href" in a and not inert and foreign == 0:
            c.base_href = a.get("href", "")[:2100]
    elif tag in ("img", "image", "picture"):
        c.images = True
        if tag == "img":
            src = a.get("src", "").strip()
            if src and not src.lower().startswith("data:") and len(c.image_urls) < 3:
                c.image_urls.append(src[:2100])
            c.attr(a.get("alt", ""))
            c.logos.append(a.get("alt", "")[:200])
            c.logos.append(_basename_words(a.get("src", ""))[:200])
    elif tag == "svg":
        c.images = True
    elif tag in ("a", "area"):
        href = a.get("href") or a.get("xlink:href")
        if href and len(c.links) < MAX_LINKS:
            c.links.append([href[:2100], a.get("alt", "")[:200] if tag == "area" else "", tag])
            if tag == "a":
                child_link = len(c.links) - 1
    elif tag == "form":
        c.form_actions.append(a.get("action", "")[:2100])
        if a.get("method", "").strip().lower() in ("", "get") and a.get("action", "").strip():
            c.get_forms.append(a.get("action", "")[:2100])
        if a.get("method", "").strip().lower() == "post":
            c.post_forms += 1
    elif tag in ("option", "optgroup", "track"):
        c.attr(a.get("label", ""))
    elif tag == "label":
        if len(c.labels) < 200:
            c.labels.append("")
            child_label = len(c.labels) - 1
    elif tag == "button":
        c.buttons += 1
    elif tag in EMBEDS:
        if tag == "iframe" and "srcdoc" in a:
            if len(c.srcdocs) < 4:
                c.srcdocs.append(a.get("srcdoc", "")[:MAX_SRCDOC])
        else:
            src = (a.get("data", "") if tag == "object" else a.get("src", "")).strip()
            if not src:
                c.empty_frames += 1
            if len(c.frames) < MAX_FRAMES:
                c.frames.append(src[:2100])
    elif tag == "template":
        # Etkisiz belge parcasi: tarayici cizmez (bildirimsel golge kok ise CIZER). Icerik her iki durumda
        # da incelenir; etkisiz sablonun metni "gizli" sayilir, yonlendirmesi izlenmez.
        shadow = a.get("shadowrootmode", "").strip().lower() in ("open", "closed")
        try:
            fragments = node.template_fragments() or []
        except Exception:
            fragments = []
        child_extra_state = (0, hid, vis, fs0, False, True if not shadow else inert, None, None, False, False)
        extra_children = [(f, child_extra_state) for f in fragments]

    if "formaction" in a:
        c.formactions.append(a.get("formaction", "")[:2100])

    if tag in ("input", "select", "textarea"):
        kind = a.get("type", "").strip().lower()
        c.all_inputs += 1
        # Girdinin ekranda cizilen metni (G-06): deger ve yer tutucu oznitelikte durur, metin dugumu degildir
        if kind not in ("hidden", "password") and tag == "input":
            c.attr(a.get("value", ""))
            c.attr(a.get("placeholder", ""))
        elif tag == "textarea":
            c.attr(a.get("placeholder", ""))
        if tag == "input" and kind in ("submit", "button", "image", "reset"):
            c.buttons += 1
        elif tag == "input" and kind == "hidden":
            pass  # gizli girdi kullanicidan bilgi istemez; "form var" sayilmaz (A-02)
        else:
            # Tarayici TANIMADIGI tur degerini (type="metin") metin kutusu olarak cizer; tarih / saat turleri de
            # kullanicidan veri alir. Metin girdisi OLMAYAN turler sayilir, gerisi metin girdisidir.
            textual = tag != "input" or kind not in ("checkbox", "radio", "file", "range", "color")
            if textual:
                c.text_inputs += 1
                if tag != "select":
                    c.free_inputs += 1
            if tag == "input" and kind == "password":
                c.password_inputs += 1
            # Parola alani type=text + maske stiliyle yazilabilir (E-10)
            masked = "-webkit-text-security" in decls and decls["-webkit-text-security"] not in ("none", "")
            if masked:
                c.masked_inputs = True
                c.password_inputs += 1
            if len(c.inputs) < MAX_INPUTS:
                descriptor = " ".join([kind, a.get("name", ""), a.get("id", ""), a.get("placeholder", ""),
                                       a.get("autocomplete", ""), a.get("aria-label", ""), a.get("title", ""),
                                       "password-masked" if masked else ""]).lower()
                c.inputs.append(descriptor[:600])
                if a.get("aria-labelledby"):
                    c._label_refs.append((len(c.inputs) - 1, a["aria-labelledby"][:200]))
                if textual:
                    cap = c.caption()
                    if cap:
                        c.captions.append(cap)

    child_state = (child_foreign, hid, vis, fs0, child_no_text, inert, child_link, child_label, child_h1, prom)
    exit_info = (exit_kind, block) if exit_kind else None
    return child_state, exit_info, extra_children
