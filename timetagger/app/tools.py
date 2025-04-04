"""
A small set of tools for authentication, storage, and communication with the server.
Or ... the minimum tools to handle the above things.
"""

from pscript.stubs import window, JSON, localStorage, location, console, fetch, Date


# %% General


def sleepms(ms):
    global RawJS
    return RawJS("new Promise(resolve => setTimeout(resolve, ms))")


def copy_dom_node(node):
    global document

    # Select the node (https://stackoverflow.com/questions/400212)
    sel = None
    if document.createRange and window.getSelection:  # FF, Chrome, Edge, ...
        range = document.createRange()
        sel = window.getSelection()
        sel.removeAllRanges()
        try:
            range.selectNodeContents(node)
            sel.addRange(range)
        except Exception:
            range.selectNode(node)
            sel.addRange(range)
    elif document.body.createTextRange:  # IE?
        range = document.body.createTextRange()
        range.moveToElementText(node)
        range.select()

    # Make a copy
    try:
        successful = window.document.execCommand("copy")
    except Exception:
        successful = False

    if not successful:
        return  # Don't unselect, user can now copy
    if sel is not None:
        sel.removeAllRanges()


def make_secure_random_string(n=8):
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ar = window.Uint32Array(n)
    window.crypto.getRandomValues(ar)
    return "".join([chars[ar[i] % len(chars)] for i in range(n)])


def dict2url(d):
    """Encode a dict in a url-part (keys and values must be str)."""
    url = ""
    for key, val in d.items():
        assert isinstance(key, str) and isinstance(val, str)
        url += key + "=" + window.encodeURIComponent(val) + "&"
    return url


def url2dict(url):
    """Decode a dict from a url-part. Strips the "#" if present."""
    url = url.lstrip("#")
    d = {}
    for pair in url.split("&"):
        key, _, val = pair.partition("=")
        if key and val:
            d[key] = window.decodeURIComponent(val)
    return d


# %% A service for long-running timers

# This allows registering functions to be called on a (long) interval.
# The setInterval timer behaves inpredictable when the computer is e.g.
# asleep. Instead we have a check-function that will fire timers when
# its their time. We can run this check function much more often, and
# e.g. on a visibility change.

_long_timers = {}


def register_long_timer_in_secs(name, interval, func):
    """Register a function to be called each interval seconds. Precision is ~ 10s."""
    now_secs = window.Date().getTime() / 1000
    _long_timers[name] = dict(
        interval=interval, func=func, next_time=now_secs + interval
    )


def _check_long_timers():
    now_secs = window.Date().getTime() / 1000
    for name, ob in _long_timers.items():
        if ob.next_time < now_secs:
            try:
                ob.func()
            except Exception as err:
                console.warn(err)
            ob.next_time = now_secs + ob.interval


window.setInterval(_check_long_timers, 10 * 1000)  # 10 s
document.addEventListener("visibilitychange", _check_long_timers, False)


# %% Connecting with server


def build_api_url(suffix):
    if "/app/" in location.pathname:
        rootpath = location.pathname.split("/app/")[0]
    else:
        rootpath = location.pathname.rpartition("/")[0]
    url = location.protocol + "//" + location.hostname + ":" + location.port
    url = url.rstrip(":") + rootpath + "/api/v2/"
    return url + suffix


# %% Authentication


def get_auth_info():
    """Get the authentication info or None."""
    console.log("[tools.py] get_auth_info called.")
    try:
        auth_info_str = localStorage.getItem("timetagger_auth_info")
        token = localStorage.getItem("timetagger_auth_token")
        
        console.log("[tools.py] timetagger_auth_info from localStorage:", 'Present' if auth_info_str else 'MISSING')
        console.log("[tools.py] timetagger_auth_token from localStorage:", 'Present' if token else 'MISSING')
        
        if auth_info_str and token:
            try:
                auth_info = JSON.parse(auth_info_str)
                if not auth_info:
                    console.warn("[tools.py] auth_info is null after parsing")
                    return None
                    
                # Ensure token is attached
                auth_info.token = token
                
                # Initialize cantuse property if not present to prevent null reference errors
                if not hasattr(auth_info, 'cantuse'):
                    auth_info.cantuse = None
                    
                console.log("[tools.py] Successfully parsed auth_info:", auth_info)
                return auth_info
            except Exception as err:
                console.warn("[tools.py] Cannot parse JSON auth info: " + str(err))
                localStorage.removeItem("timetagger_auth_info")
                localStorage.removeItem("timetagger_auth_token")
                return None
        else:
            console.log("[tools.py] No complete auth info found in storage")
            return None
    except Exception as err:
        console.error("[tools.py] Error getting auth info:", err)
        return None


def set_auth_info_from_token(token):
    """Set the authentication by providing a TimeTagger webtoken."""
    try:
        if not token:
            console.error("[tools.py] Empty token provided to set_auth_info_from_token")
            return None
            
        console.log("[tools.py] Setting auth info from token: " + token[:20] + "...")
        
        # Parse the token payload
        token_parts = token.split(".")
        if len(token_parts) < 2:
            console.error("[tools.py] Invalid token format - not enough parts")
            return None
            
        payload_base64 = token_parts[1].replace("_", "/")
        # Add padding if needed
        padding = 4 - (len(payload_base64) % 4)
        if padding != 4:
            payload_base64 += "=" * padding
            
        decoded_text = window.decodeURIComponent(window.escape(window.atob(payload_base64)))
        auth_info = JSON.parse(decoded_text)
        
        if not auth_info:
            console.error("[tools.py] Failed to parse token payload")
            return None
            
        # Ensure token is attached to the auth_info
        auth_info.token = token
        
        # Initialize cantuse property if not present to prevent null reference errors
        if not hasattr(auth_info, 'cantuse'):
            auth_info.cantuse = None
        
        # Store both the full auth info and the token separately
        localStorage.setItem("timetagger_auth_info", JSON.stringify(auth_info))
        localStorage.setItem("timetagger_auth_token", token)
        
        console.log("[tools.py] Auth info and token stored successfully")
        console.log("[tools.py] Username: " + auth_info.username)
        console.log("[tools.py] Is admin: " + String(auth_info.is_admin))
        
        # Using Date in Python-transpiled code requires window.Date
        expiry_date = window.Date(auth_info.expires * 1000)
        console.log("[tools.py] Expires: " + expiry_date.toISOString())
        
        return auth_info
    except Exception as err:
        console.error("[tools.py] Error storing auth info:", err)
        return None


async def logout():
    """Log the user out by discarting auth info. Await this call!"""
    # Forget the JWT and associated info.
    localStorage.setItem("timetagger_auth_info", "")
    localStorage.setItem("timetagger_auth_token", "")

    # Forget our cache. Note that this is async.
    await AsyncStorage().clear()


async def renew_webtoken(verbose=True, reset=False):
    """Renew the webtoken. Each webtoken expires after 14 days. But
    while valid, it can be exhcanged for a new one. By doing this while
    the app is active, users won't be logged out unless this device
    does not use the app for 14 days.

    If reset is True, the token seed is reset, causing all issued web
    tokens to become invalid. In other words: all sessions on other
    devices will be logged out.
    """
    # Get current auth info
    auth = get_auth_info()
    if not auth:
        if verbose:
            console.warn("Could not renew token - not logged in")
        return

    # Make request and wait for response
    url = build_api_url("webtoken")
    if reset:
        url += "?reset=1"
    init = dict(method="GET", headers={"authtoken": auth.token})
    res = await fetch(url, init)

    # Handle
    if res.status != 200:
        text = await res.text()
        console.warn("Could not renew token: " + text)
        if res.status == 401 and "revoked" in text:
            # When revoked, we logout to drop local changes.
            # See notes in stores.py where we do the same.
            if "/app/" in location.pathname:
                location.href = "../logout"
            else:
                location.href = "./logout"
        return

    # Are we still logged in. User may have logged out in the mean time.
    auth = get_auth_info()
    if not auth:
        return

    # Apply - handle both JSON response and direct token string
    response_text = await res.text()
    token = None
    
    try:
        # Try to parse as JSON first
        d = JSON.parse(response_text)
        if d and d.token:
            token = d.token
        else:
            # Maybe it's a JSON object without a token property
            console.warn("JSON response doesn't contain token property")
    except Exception:
        # If not valid JSON, assume the response is the token itself
        if response_text.startsWith("eyJ"):  # Simple check for JWT format
            token = response_text
        else:
            console.error("Invalid token format received")
            return
    
    if token:
        new_token_info = set_auth_info_from_token(token)
        
        # If admin status changed, reload the page to update UI
        if auth.is_admin != new_token_info.is_admin:
            console.warn("Admin status changed, reloading page")
            location.reload()
        
        if verbose:
            console.warn("webtoken renewed")
    else:
        console.error("Token renewal failed - no valid token received")


# Renew token now, and set up to renew each hour
window.addEventListener("load", lambda: renew_webtoken())
register_long_timer_in_secs("renew_webtoken", 3600, lambda: renew_webtoken(False))


# %% Storage


class AsyncStorage:
    """A kind of localstorage API, but async and without the 5MB memory
    restriction, based on IndexedDB.
    """

    _dbname = "timeturtle"
    _dbstorename = "cache"
    _dbversion = 1

    async def clear(self):
        """Async delete all items from the cache."""

        def executor(resolve, reject):
            on_error = lambda e: reject(self._error_msg(e))

            def on_db_ready(e):
                db = e.target.result
                db.onerror = on_error
                transaction = db.transaction([self._dbstorename], "readwrite")
                request = transaction.objectStore(self._dbstorename).clear()
                request.onsuccess = lambda: resolve(None)

            request = window.indexedDB.open(self._dbname, self._dbversion)
            request.onerror = on_error
            request.onupgradeneeded = self._on_update_required
            request.onsuccess = on_db_ready

        return await window.Promise(executor)

    async def setItem(self, ob):
        """Async put an object in the db."""
        if not ob.key:
            raise KeyError("Object must have a 'key' property")

        def executor(resolve, reject):
            on_error = lambda e: reject(self._error_msg(e))

            def on_db_ready(e):
                db = e.target.result
                db.onerror = on_error
                transaction = db.transaction([self._dbstorename], "readwrite")
                request = transaction.objectStore(self._dbstorename).put(ob)
                request.onsuccess = lambda: resolve(None)

            request = window.indexedDB.open(self._dbname, self._dbversion)
            request.onerror = on_error
            request.onupgradeneeded = self._on_update_required
            request.onsuccess = on_db_ready

        return await window.Promise(executor)

    async def getItem(self, key):
        """Async get an object from the db."""

        def executor(resolve, reject):
            on_error = lambda e: reject(self._error_msg(e))

            def on_db_ready(e):
                db = e.target.result
                db.onerror = on_error
                transaction = db.transaction([self._dbstorename], "readonly")
                request = transaction.objectStore(self._dbstorename).get(key)
                request.onsuccess = lambda e: resolve(e.target.result)

            request = window.indexedDB.open(self._dbname, self._dbversion)
            request.onerror = on_error
            request.onupgradeneeded = self._on_update_required
            request.onsuccess = on_db_ready

        return await window.Promise(executor)

    def _error_msg(self, e):
        msg = "IndexDB error"
        if e.target.errorCode:
            msg += " (" + e.target.errorCode + ")"
        if e.target.error:
            msg += ": " + e.target.error
        return msg

    def _on_update_required(self, e):
        # This is where we structure the database.
        # Gets called before db_open_request.onsuccess.
        db = e.target.result
        for i in range(len(db.objectStoreNames)):
            db.deleteObjectStore(db.objectStoreNames[i])
        db.createObjectStore(self._dbstorename, {"keyPath": "key"})
