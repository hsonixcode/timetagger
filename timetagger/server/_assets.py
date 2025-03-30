"""
The asset server. All assets are loaded on startup and served from
memory, thus allowing blazing fast serving.
"""

import os
import re
import hashlib
import logging
from importlib import resources

import jinja2
import pscript
import markdown

from . import _utils as utils
from .. import __version__


versionstring = "v" + __version__


logger = logging.getLogger("asgineer")

IMAGE_EXTS = ".png", ".jpg", ".gif", ".ico", ".mp4", ".svg"
FONT_EXTS = ".ttf", ".otf", ".woff", ".woff2"
AUDIO_EXTS = ".wav", ".mp3", ".ogg"

re_fas = re.compile(r"\>(\\uf[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F])\<")

default_template = (
    open(resources.files("timetagger.common") / "_template.html", "rb").read().decode()
)


def _get_base_style():
    fname = resources.files("timetagger.common") / "_style_embed.scss"
    with open(fname, "rb") as f:
        text = f.read().decode()
    return utils.get_scss_vars(text), utils.compile_scss_to_css(text)


style_vars, style_embed = _get_base_style()


def compile_scss(text):
    return utils.compile_scss_to_css(text, **style_vars)


def md2html(text, template):
    title = description = ""
    if text.startswith("%"):
        title, text = text.split("\n", 1)
        title = title.strip("% \t\r\n")
    if text.startswith("%"):
        description, text = text.split("\n", 1)
        description = description.strip("% \t\r\n")
    title = title or "TimeTagger"
    description = description or title
    assert '"' not in description
    
    # Process template variables in the text first
    if isinstance(template, dict):
        # If template is a dict, create a new Template from default_template
        template_obj = jinja2.Template(default_template)
    elif isinstance(template, str):
        template_obj = jinja2.Template(template)
    else:
        template_obj = template
    
    # Create text template and render with context
    text_template = jinja2.Template(text)
    text = text_template.render(
        timetagger_azure_client_id=template.get('timetagger_azure_client_id', '') if isinstance(template, dict) else '',
        timetagger_azure_tenant_id=template.get('timetagger_azure_tenant_id', '') if isinstance(template, dict) else '',
        timetagger_azure_client_secret=template.get('timetagger_azure_client_secret', '') if isinstance(template, dict) else '',
        timetagger_azure_redirect_uri=template.get('timetagger_azure_redirect_uri', '') if isinstance(template, dict) else ''
    )
    
    # Convert font-awesome codepoints to Unicode chars
    for match in reversed(list(re_fas.finditer(text))):
        text = (
            text[: match.start(1)]
            + eval("'" + match.group(1) + "'")
            + text[match.end(1) :]
        )
    # Some per-line tweaks (turn some headers into anchors, e.g. in support page)
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.startswith(("## ", "### ")) and "|" in line:
            pre, header = line.split(" ", 1)
            linkname, header = header.split("|", 1)
            pre, linkname, line = pre.strip(), linkname.strip(), header.strip()
            line = f"<a name='{linkname}' href='#{linkname}'>{header}</a>"
            line = f"<h{len(pre)}>{line}</h{len(pre)}>"
            lines[i] = line
    text = "\n".join(lines)
    # Turn md into html and store
    main = markdown.markdown(text, extensions=["fenced_code"])

    # Render final template with all variables
    return template_obj.render(
        title=title,
        description=description,
        main=main,
        embedded_script="",
        embedded_style=style_embed,
        versionstring=versionstring,
        timetagger_azure_client_id=template.get('timetagger_azure_client_id', '') if isinstance(template, dict) else '',
        timetagger_azure_tenant_id=template.get('timetagger_azure_tenant_id', '') if isinstance(template, dict) else '',
        timetagger_azure_client_secret=template.get('timetagger_azure_client_secret', '') if isinstance(template, dict) else '',
        timetagger_azure_redirect_uri=template.get('timetagger_azure_redirect_uri', '') if isinstance(template, dict) else ''
    )


def create_assets_from_dir(dirname):
    """Get a dictionary of assets from a directory."""
    assets = {}

    thtml = default_template
    try:
        # Get template from the module's resources
        thtml = resources.files(dirname).joinpath("_template.html").read_text()
    except (FileNotFoundError, IsADirectoryError):
        pass
    template = jinja2.Template(thtml)

    try:
        # Get all files in the directory using importlib.resources
        for file in resources.files(dirname).iterdir():
            fname = file.name
            if fname.startswith("_") and fname != "_template.html":
                continue
            elif fname.endswith(".md"):
                # Turn markdown into HTML
                text = file.read_text()
                html = md2html(text, template)
                name, ext = os.path.splitext(fname)
                assets["" if name == "index" else name] = html
            elif fname.endswith((".scss", ".sass")):
                # An scss/sass file, a preprocessor of css
                text = file.read_text()
                assets[fname[:-5] + ".css"] = compile_scss(text)
            elif fname.endswith(".html"):
                # Raw HTML - skip _template.html as it's handled separately
                if fname == "_template.html":
                    continue 
                text = file.read_text()
                assets[fname[:-5]] = text
            elif fname.endswith(".py"):
                # Turn Python into JS
                name, ext = os.path.splitext(fname)
                # Compile
                pycode = file.read_text()
                parser = pscript.Parser(pycode, str(file))
                jscode = "/* Do not edit, autogenerated by pscript */\n\n" + parser.dump()
                # Wrap in module
                exports = [
                    name for name in parser.vars.get_defined() if not name.startswith("_")
                ]
                exports.sort()  # important to produce reproducable assets
                jscode = pscript.create_js_module(name, jscode, [], exports, "simple")
                # Store as string, not bytes
                assets[fname[:-2] + "js"] = jscode
                logger.info(f"Compiled pscript from {fname}")
            elif fname.endswith((".txt", ".js", ".css", ".json")):
                # Text assets
                assets[fname] = file.read_text()
            elif fname.endswith(IMAGE_EXTS + FONT_EXTS + AUDIO_EXTS):
                # Binary assets
                assets[fname] = file.read_bytes()
            else:
                continue  # Skip unknown extensions

        logger.info(f"Collected {len(assets)} assets from {dirname}")
    except Exception as e:
        logger.error(f"Error collecting assets from {dirname}: {str(e)}")
        raise

    return assets


def enable_service_worker(assets):
    """Enable the service worker 'sw.js', by giving it a cacheName
    based on a hash from all the assets.
    """
    assert "sw.js" in assets, "Expected sw.js in assets"
    sw = assets.pop("sw.js")

    # Generate hash based on content. Use sha1, just like Git does.
    hash = hashlib.sha1()
    for key in sorted(assets.keys()):
        content = assets[key]
        content = content.encode() if isinstance(content, str) else content
        hash.update(content)

    # Generate cache name. The name must start with "timetagger" so
    # that old caches are cleared correctly. We include the version
    # string for clarity. The hash is the most important part. It
    # ensures that the SW is considered new whenever any of the assets
    # change. It also means that two containers serving the same assets
    # use the same hash.
    hash_str = hash.hexdigest()[:12]  # 6 bytes should be more than enough
    cachename = f"timetagger_{versionstring}_{hash_str}"

    # Produce list of assets. If we don't replace this, we get the default SW
    # behavior, which is not doing any caching, essentially being a no-op.
    asset_list = list(sorted(assets.keys()))

    # Update the code
    replacements = {
        "timetagger_cache": cachename,
        "assets = [];": f"assets = {asset_list};",
    }
    for needle, replacement in replacements.items():
        assert needle in sw, f"Expected {needle} in sw.js"
        sw = sw.replace(needle, replacement, 1)
    assets["sw.js"] = sw
