"""
This implements the API side of the server.
"""

import json
import time
import logging
import secrets

from sqlalchemy.orm import Session

from ._utils import create_jwt, decode_jwt
from .db_utils import get_session, Record, Settings, UserInfo, UserInfoKeyValue

logger = logging.getLogger("asgineer")

# At the server:
#
# * We specify the fields that an item has (that the server accepts).
# * We specify a subset of those that are required. This allows more flexibility
#   in clients, and helps when we add fields at the server, but have old clients.
# * We specify how the incoming values are converted/checked.
# * Other incoming fields are simply ignored.
# * There is a special field st (server time) that the server adds to each item.
# * We have tests to ensure that the lines below line up with the same
#   values in client/stores.py.

to_int = int
to_float = float

STR_MAX = 256
JSON_MAX = 8192

def to_str(s):
    s = str(s)
    if len(s) >= STR_MAX:
        raise ValueError("String values must be less than 256 chars.")
    return s


def to_jsonable(x):
    s = json.dumps(x)
    if len(s) >= JSON_MAX:
        raise ValueError("Values must be less than 256 chars when jsonized.")
    return x

# Define requirements and specs first with direct values
REQS = {
    "records": ["key", "mt", "t1", "t2"],
    "settings": ["key", "mt", "value"],
}

SPECS = {
    "records": dict(key=to_str, mt=to_int, t1=to_int, t2=to_int, ds=to_str),
    "settings": dict(key=to_str, mt=to_int, value=to_jsonable),
}

# ----- COMMON PART (don't change this comment)

RECORD_SPEC = dict(key=to_str, mt=to_int, t1=to_int, t2=to_int, ds=to_str)
RECORD_REQ = ["key", "mt", "t1", "t2"]

SETTING_SPEC = dict(key=to_str, mt=to_int, value=to_jsonable)
SETTING_REQ = ["key", "mt", "value"]

# Update the REQS and SPECS with the defined constants
REQS["records"] = RECORD_REQ
REQS["settings"] = SETTING_REQ
SPECS["records"] = RECORD_SPEC
SPECS["settings"] = SETTING_SPEC

# ----- END COMMON PART (don't change this comment)

# Map model classes to table names
MODEL_MAP = {
    "records": Record,
    "settings": Settings,
    "userinfo": UserInfo,
}


class AuthException(Exception):
    """Exception raised when authentication fails.
    You should catch this error and respond with 401 unauthorized.
    """

    def __init__(self, msg):
        super().__init__(msg)


# Context manager for session management
class DBSessionContext:
    """Context manager for database sessions"""
    
    def __init__(self, username):
        self.username = username
        self.session = None
    
    async def __aenter__(self):
        self.session = get_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.session.rollback()
        else:
            self.session.commit()
        self.session.close()
    
    async def select_one(self, table_name, condition, *args):
        """Select a single record from the database based on a condition"""
        model_class = MODEL_MAP[table_name]
        
        query = self.session.query(model_class)
        
        # Parse the condition to create a SQLAlchemy filter
        if condition.startswith("key =="):
            key = args[0] if args else condition.split("==")[1].strip().strip('"\'')
            query = query.filter(model_class.key == key)
        
        # Add username filter
        query = query.filter(model_class.username == self.username)
        
        # Execute the query and get the first result
        result = query.first()
        
        # Convert to dictionary if result exists
        if result:
            return {c.name: getattr(result, c.name) for c in result.__table__.columns}
        return None
    
    async def select_all(self, table_name, condition=None, *args):
        """Select all records from the database based on optional condition"""
        model_class = MODEL_MAP[table_name]
        
        query = self.session.query(model_class)
        
        # Parse the condition to create a SQLAlchemy filter if provided
        if condition:
            try:
                if ">" in condition:
                    field, value = condition.split(">")
                    field = field.strip()
                    # Handle the case where args[0] might be a question mark
                    if args and args[0] != '?':
                        try:
                            value = float(args[0])
                        except (TypeError, ValueError):
                            # If we can't convert args[0], use the value from condition string
                            value = float(value.strip())
                    else:
                        value = float(value.strip())
                    query = query.filter(getattr(model_class, field) > value)
                elif "<" in condition:
                    field, value = condition.split("<")
                    field = field.strip()
                    # Handle the case where args[0] might be a question mark
                    if args and args[0] != '?':
                        try:
                            value = float(args[0])
                        except (TypeError, ValueError):
                            # If we can't convert args[0], use the value from condition string
                            value = float(value.strip())
                    else:
                        value = float(value.strip())
                    query = query.filter(getattr(model_class, field) < value)
            except Exception as e:
                logger.error(f"Error parsing condition '{condition}' with args {args}: {e}")
                # Continue without applying the filter
        
        # Add username filter
        query = query.filter(model_class.username == self.username)
        
        # Execute the query and get all results
        results = query.all()
        
        # Convert to dictionaries
        return [{c.name: getattr(result, c.name) for c in result.__table__.columns} for result in results]
    
    async def put(self, table_name, item):
        """Insert or update an item in the database"""
        model_class = MODEL_MAP[table_name]
        
        # Add username to the item
        item['username'] = self.username
        
        # Add server time
        item['st'] = time.time()
        
        # Check if item exists
        existing = self.session.query(model_class).filter(
            model_class.key == item['key'],
            model_class.username == self.username
        ).first()
        
        if existing:
            # Update existing item
            for key, value in item.items():
                setattr(existing, key, value)
        else:
            # Create new item
            new_item = model_class(**item)
            self.session.add(new_item)
    
    async def delete(self, table_name, condition):
        """Delete records matching a condition"""
        model_class = MODEL_MAP[table_name]
        
        query = self.session.query(model_class)
        
        # Parse the condition
        if condition == "t1 = t2":
            query = query.filter(model_class.t1 == model_class.t2)
        
        # Add username filter
        query = query.filter(model_class.username == self.username)
        
        # Delete the records
        query.delete(synchronize_session=False)
    
    async def ensure_table(self, table_name):
        """Ensure the table exists - no-op in PostgreSQL as tables are created at startup"""
        # Tables are created at DB initialization, nothing needed here
        pass
    
    async def delete_table(self, table_name):
        """Delete all records in a table for this user"""
        model_class = MODEL_MAP[table_name]
        
        # Delete all records for this user
        self.session.query(model_class).filter(
            model_class.username == self.username
        ).delete(synchronize_session=False)
    
    async def rename_table(self, old_name, new_name):
        """Move all records from one table to another"""
        # Get the model classes
        old_model = MODEL_MAP[old_name]
        new_model = MODEL_MAP[new_name]
        
        # Query all records from old table for this user
        old_records = self.session.query(old_model).filter(
            old_model.username == self.username
        ).all()
        
        # Convert to dictionaries
        items = [{c.name: getattr(record, c.name) for c in record.__table__.columns} for record in old_records]
        
        # Delete from old table
        self.session.query(old_model).filter(
            old_model.username == self.username
        ).delete(synchronize_session=False)
        
        # Insert into new table
        for item in items:
            new_record = new_model(**item)
            self.session.add(new_record)


# %% Main handler

# todo: rate limiting


async def api_handler_triage(request, path, auth_info, db):
    """The API handler that triages over the API options."""

    # Handle versioned API paths
    if path.startswith('v2/'):
        path = path[3:]  # Remove 'v2/' prefix

    if path == "updates":
        if request.method == "GET":
            return await get_updates(request, auth_info, db)
        else:
            expl = "/updates can only be used with GET"
            return 405, {}, "method not allowed: " + expl

    elif path == "records":
        if request.method == "GET":
            return await get_records(request, auth_info, db)
        elif request.method == "PUT":
            return await put_records(request, auth_info, db)
        else:
            expl = "/records can only be used with GET and PUT"
            return 405, {}, "method not allowed: " + expl

    elif path == "settings":
        if request.method == "GET":
            return await get_settings(request, auth_info, db)
        elif request.method == "PUT":
            return await put_settings(request, auth_info, db)
        else:
            expl = "/settings can only be used with GET and PUT"
            return 405, {}, "method not allowed: " + expl

    elif path == "forcereset":
        if request.method == "PUT":
            return await put_forcereset(request, auth_info, db)
        else:
            expl = "/forcereset can only be used with PUT"
            return 405, {}, "method not allowed: " + expl

    elif path == "webtoken":
        if request.method in ("GET"):
            return await get_webtoken(request, auth_info, db)
        else:
            expl = "/webtoken can only be used with GET"
            return 405, {}, "method not allowed: " + expl

    elif path == "apitoken":
        if request.method in ("GET"):
            return await get_apitoken(request, auth_info, db)
        else:
            expl = "/apitoken can only be used with GET"
            return 405, {}, "method not allowed: " + expl

    else:
        expl = f"/{path} is not a valid API path"
        return 404, {}, "not found: " + expl


# %% Auth


WEBTOKEN_DAYS = 2 * 7
WEBTOKEN_LIFETIME = WEBTOKEN_DAYS * 24 * 60 * 60
API_TOKEN_EXP = 32503748400  # the year 3000


async def authenticate(request):
    """Authenticate the user, returning (auth_info, db) if all is well.
    Raises AuthException if an authtoken is missing, not issued by us,
    does not match the seed (i.e. has been revoked), or has expired.
    """

    st = time.time()

    # Get jwt from header. Validates that a token is provided.
    token = request.headers.get("authtoken", "")
    if not token:
        raise AuthException("Missing jwt 'authtoken' in header.")

    # Decode the jwt to get auth_info. Validates that we created it.
    try:
        auth_info = decode_jwt(token)
    except Exception as err:
        raise AuthException(str(err))

    # Create database session context
    db = DBSessionContext(auth_info["username"])
    
    # Ensure tables exist (no-op in PostgreSQL, but kept for compatibility)
    await db.__aenter__()
    await db.ensure_table("userinfo")
    await db.ensure_table("records")
    await db.ensure_table("settings")
    await db.__aexit__(None, None, None)
    
    # Create a fresh session context
    db = DBSessionContext(auth_info["username"])

    # Get reference seed from db
    expires = auth_info["expires"]
    tokenkind = "apitoken" if expires > st + WEBTOKEN_LIFETIME else "webtoken"
    ref_seed = await _get_token_seed_from_db(db, tokenkind, False)

    # Compare seeds. Validates that the token is not revoked.
    if not ref_seed or ref_seed != auth_info["seed"]:
        raise AuthException(f"The {tokenkind} is revoked (seed does not match)")

    # Check expiration last. Validates that the token is not too old.
    # If a token is both revoked and expired, we want to emit the revoked-message.
    if auth_info["expires"] < st:
        raise AuthException(f"The {tokenkind} has expired (after {WEBTOKEN_DAYS} days)")

    # All is well!
    return auth_info, db


async def get_webtoken(request, auth_info, db):
    # Get reset option
    reset = False
    if request.querydict and "reset" in request.querydict:
        reset = True
    
    # Return token
    webtoken, db_seed = await _get_any_token(auth_info, db, "webtoken", reset)
    return 200, {}, webtoken


async def get_apitoken(request, auth_info, db):
    # Get reset option
    reset = False
    if request.querydict and "reset" in request.querydict:
        reset = True
    
    # Return token
    apitoken, db_seed = await _get_any_token(auth_info, db, "apitoken", reset)
    return 200, {}, apitoken


async def _get_any_token(auth_info, db, tokenkind, reset):
    username = auth_info["username"]
    
    # Check admin status
    from ..multiuser.auth_utils import check_admin_status_sync
    is_admin, source = check_admin_status_sync(auth_info)
    logger.info(f"Admin status for {username} determined as {is_admin} from {source}")
    
    # Make sure we're connected to db
    async with db:
        # Get new seed and create new token
        db_seed = await _get_token_seed_from_db(db, tokenkind, reset)
        
        # Create token
        st = time.time()
        # Use the same expiration time for both web and API tokens
        exptime = st + WEBTOKEN_LIFETIME
        
        payload = {
            "username": username,
            "expires": int(exptime),
            "seed": db_seed,
            "is_admin": is_admin,  # Include admin status in the token
            "token_type": tokenkind  # Include token type for differentiation
        }
        token = create_jwt(payload)
        logger.info(f"Generated {tokenkind} for {username} with is_admin={is_admin}, expires in {WEBTOKEN_DAYS} days")
        
        # Done!
        return token, db_seed


async def _get_token_seed_from_db(db, tokenkind, reset):
    # Get seed using UserInfoKeyValue
    username = db.username
    key = tokenkind + "_seed"
    
    # Import here to avoid circular imports
    from .db_utils import UserInfoKeyValue
    
    if reset:
        # Generate new seed and save it
        new_seed = secrets.token_urlsafe(9)
        user_info = UserInfoKeyValue(
            username=username,
            key=key,
            value=new_seed,
            mt=time.time(),
            st=time.time()
        )
        UserInfoKeyValue.save(user_info)
        return new_seed
    else:
        # Try to get existing seed
        user_info = UserInfoKeyValue.get_by_username_and_key(username, key)
        if user_info is not None:
            return user_info.value
        else:
            # No seed exists, create a new one
            return await _get_token_seed_from_db(db, tokenkind, True)


async def get_webtoken_unsafe(username, reset=False, is_admin=None):
    """Generate a webtoken for the given user. The seed for the token is
    retrieved from the user's db. If no seed exists yet, it is generated.
    
    This function is unsafe in that it does not check credentials. The
    caller of this function MUST take care of that.
    """
    # Check in auth_utils if is_admin is available
    from ..multiuser.auth_utils import check_admin_status_sync
    
    # Get and prep db
    db = DBSessionContext(username)
    
    try:
        # Check if user is admin
        if is_admin is None:
            # Create mock auth_info for standardized check
            auth_info = {"username": username}
            is_admin, source = check_admin_status_sync(auth_info)
            logger.info(f"Admin status for {username} determined as {is_admin} from {source}")
        
        # Ensure tables exist
        await db.__aenter__()
        await db.ensure_table("userinfo")
        await db.ensure_table("records")
        await db.ensure_table("settings")
        
        # Get seed using the direct access method
        db_seed = None
        
        # Try to get the seed
        user_info = UserInfoKeyValue.get_by_username_and_key(username, "webtoken_seed")
        if user_info is not None:
            db_seed = user_info.value
        
        # Create new if needed
        if reset or db_seed is None:
            db_seed = secrets.token_urlsafe(9)
            
            # Create or update the seed using UserInfoKeyValue
            user_info = UserInfoKeyValue(
                username=username,
                key="webtoken_seed",
                value=db_seed,
                mt=time.time(),
                st=time.time()
            )
            UserInfoKeyValue.save(user_info)
        
        # Create token
        st = time.time()
        payload = {
            "username": username,
            "expires": int(st + WEBTOKEN_LIFETIME),
            "seed": db_seed,
            "is_admin": is_admin  # Include admin status in the token
        }
        token = create_jwt(payload)
        logger.info(f"Generated token for {username} with is_admin={is_admin}")
        
        await db.__aexit__(None, None, None)
        
        return token
        
    except Exception as e:
        logger.error(f"Error in get_webtoken_unsafe: {e}")
        await db.__aexit__(type(e), e, e.__traceback__)
        raise


# %% Records and settings


async def get_updates(request, auth_info, db):
    # Parse since
    since = 0
    if request.querydict and "since" in request.querydict:
        try:
            since_str = request.querydict["since"]
            # Handle the case where since might be a questionmark or invalid value
            if since_str and since_str != '?':
                since = float(since_str)
            logger.info(f"Processing updates request with since={since}")
        except Exception as err:
            logger.error(f"Error parsing 'since' parameter: {err}, defaulting to since=0")
            # Continue with since=0 as a fallback
    
    # Get items
    items = {"records": [], "settings": []}
    
    async with db:
        # Get reset time
        ob = await db.select_one("userinfo", "key == ?", "reset_time")
        reset_time = float((ob or {}).get("value", -1))
        
        # Get records
        records = await db.select_all("records", "st > ?", since)
        for rec in records:
            if rec["st"] > since:
                items["records"].append(rec)
        
        # Get settings
        settings = await db.select_all("settings", "st > ?", since)
        for rec in settings:
            if rec["st"] > since:
                items["settings"].append(rec)
    
    # Return data
    items["reset"] = reset_time > since
    server_time = time.time()
    items["server_time"] = server_time
    
    # We *could* simply return items, and have our asgi server serialize
    # it, but that would be a mess to read. Plus now we get to specify
    # the max digits for floats, which is a plus in our case, because we
    # have so many timestamps.
    s = json.dumps(items, separators=(",", ":"))
    return 200, {"Content-Type": "application/json"}, s


async def get_records(request, auth_info, db):
    # Parse timerange option
    if not (request.querydict and "timerange" in request.querydict):
        return 400, {}, "Missing timerange"
    try:
        timerange_str = request.querydict["timerange"]
        parts = timerange_str.split("-")
        if len(parts) != 2:
            raise ValueError("timerange must be t1-t2")
        t1, t2 = float(parts[0]), float(parts[1])
    except Exception as err:
        return 400, {}, "Invalid value for timerange: " + str(err)
    
    # Get records
    records = []
    async with db:
        for rec in await db.select_all("records"):
            if rec["t2"] >= t1 and rec["t1"] <= t2:
                records.append(rec)
    
    # Return data
    server_time = time.time()
    items = {"records": records, "server_time": server_time}
    s = json.dumps(items, separators=(",", ":"))
    return 200, {"Content-Type": "application/json"}, s


async def put_records(request, auth_info, db):
    return await _push_items(request, auth_info, db, "records")


async def get_settings(request, auth_info, db):
    # Collect settings
    settings = []
    async with db:
        async for rec in db.select_all("settings"):
            settings.append(rec)
    server_time = time.time()
    items = {"settings": settings, "server_time": server_time}
    s = json.dumps(items, separators=(",", ":"))
    return 200, {"Content-Type": "application/json"}, s


async def put_settings(request, auth_info, db):
    return await _push_items(request, auth_info, db, "settings")


async def _push_items(request, auth_info, db, what):
    # Download items
    items = await request.get_json(10 * 2**20)  # 10 MiB limit
    if not isinstance(items, list):
        raise TypeError(f"List of {what} must be a list")

    server_time = time.time()

    req = REQS[what]
    spec = SPECS[what]

    accepted = []  # keys of accepted items (but might have mt < current)
    failed = []  # keys of corrupt items
    errors = []  # error messages, matching up with failed
    errors2 = []  # error messages for items that did not even have a key

    async with db:
        ob = await db.select_one("userinfo", "key == ?", "reset_time")
        reset_time = float((ob or {}).get("value", -1))

        for item in items:
            # First check minimal requirement.
            if not (isinstance(item, dict) and isinstance(item.get("key", None), str)):
                errors2.append("Got item that is not a dict with str 'key' field.")
                continue

            # Get current item (or None). We will ALWAYS update the item's st
            # (except when cur_item is None and incoming is corrupt).
            # This helps guarantee consistency between server and client.
            cur_item = await db.select_one(what, "key == ?", item["key"])

            # Skip if its older
            if (
                cur_item is not None
                and item.get("mt", 0) <= cur_item.get("mt", 0)
                and not reset_time > cur_item.get("mt", 0)
            ):
                accepted.append(item["key"])
                continue

            # Verify that the item is valid
            try:
                new_item = {}
                # Check that all required fields are present
                for key in req:
                    if key not in item:
                        raise ValueError(
                            f"Item misses {key} field (required: {', '.join(req)})"
                        )
                # Check and convert each field.
                for key, val in item.items():
                    if key in spec:
                        new_item[key] = spec[key](val)
            except Exception as err:
                failed.append(item["key"])
                errors.append(str(err))
                # if cur_item is not None: await db.put(what, cur_item)  # nope
                continue

            # Update db
            await db.put(what, new_item)
            accepted.append(item["key"])

    result = {
        "accepted": accepted,
        "failed": failed,
        "errors": errors,
        "errors2": errors2,
        "server_time": server_time,
    }
    s = json.dumps(result, separators=(",", ":"))
    return 200, {"Content-Type": "application/json"}, s


async def put_forcereset(request, auth_info, db):
    """Reset the server db, forcing the client to do the same."""
    async with db:
        server_time = time.time()
        await db.put(
            "userinfo",
            {"key": "reset_time", "value": server_time, "mt": int(server_time)},
        )
    return 200, {}, f"Reset at {int(server_time)}"
