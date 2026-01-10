from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
import httpx
import asyncio
import json
from google.protobuf import json_format, message
from Crypto.Cipher import AES
import base64

# Constants for encryption and API configuration
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB51"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = ["BR"]
ACCOUNTS = {
   
'BR': "uid=4329623275&password=OFFLINE-QLX2K1WDO"
}

async def json_to_proto(json_data: str, proto_message: message.Message) -> bytes:
    """Convert JSON data to a protobuf message and serialize it."""
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def pad(text: bytes) -> bytes:
    """Pad text to align with AES block size."""
    padding_length = AES.block_size - (len(text) % AES.block_size)
    padding = bytes([padding_length] * padding_length)
    return text + padding

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Encrypt data using AES-CBC."""
    aes = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext)
    return aes.encrypt(padded_plaintext)

def unpad(text: bytes) -> bytes:
    """Remove padding from decrypted text."""
    if not text or len(text) == 0:
        raise ValueError("Cannot unpad empty text")
    padding_length = text[-1]
    if padding_length > len(text) or padding_length == 0:
        raise ValueError(f"Invalid padding length: {padding_length}")
    return text[:-padding_length]

def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypt data using AES-CBC."""
    aes = AES.new(key, AES.MODE_CBC, iv)
    decrypted = aes.decrypt(ciphertext)
    return unpad(decrypted)

def decode_protobuf(encoded_data: bytes, message_type) -> message.Message:
    """Decode protobuf data into a message instance."""
    # Handle both class types and instances
    if isinstance(message_type, type):
        message_instance = message_type()
    else:
        message_instance = message_type
    message_instance.ParseFromString(encoded_data)
    return message_instance

def snake_to_camel(name):
    """Convert snake_case to camelCase."""
    components = name.split('_')
    return components[0] + ''.join(x.capitalize() for x in components[1:])

def protobuf_to_dict_complete(proto_message):
    """Convert protobuf message to dict, including ALL fields even if empty or default.
    Manually extracts every field from descriptor to ensure nothing is missed."""
    result = {}
    descriptor = proto_message.DESCRIPTOR
    
    # Iterate through ALL fields in descriptor - guarantee every field is included
    # Don't use ListFields() - just process every field from the descriptor
    for field in descriptor.fields:
        field_name_snake = field.name
        field_name_camel = snake_to_camel(field_name_snake)
        
        # ALWAYS add the field - no exceptions, no conditions
        try:
            if field.is_repeated():
                # Repeated field
                field_value = getattr(proto_message, field_name_snake, [])
                if field.message_type:
                    result[field_name_camel] = [protobuf_to_dict_complete(item) for item in field_value] if field_value else []
                else:
                    result[field_name_camel] = list(field_value) if field_value else []
            
            elif field.message_type:
                # Nested message
                field_value = getattr(proto_message, field_name_snake, None)
                if field_value:
                    result[field_name_camel] = protobuf_to_dict_complete(field_value)
                else:
                    result[field_name_camel] = {}
            
            else:
                # Scalar field - ALWAYS add it
                # Get the field value - protobuf returns default values for unset fields
                field_value = getattr(proto_message, field_name_snake, None)
                
                # Always add the field - use the value if it exists, otherwise use default
                # For protobuf, getattr returns default values (0, False, "") for unset fields
                # So we always have a value to use
                if field_value is not None:
                    if field.enum_type:
                        result[field_name_camel] = int(field_value)
                    else:
                        result[field_name_camel] = field_value
                else:
                    # Value is None - use default based on type
                    if field.cpp_type in [field.CPPTYPE_INT32, field.CPPTYPE_INT64,
                                          field.CPPTYPE_UINT32, field.CPPTYPE_UINT64]:
                        result[field_name_camel] = 0
                    elif field.cpp_type in [field.CPPTYPE_DOUBLE, field.CPPTYPE_FLOAT]:
                        result[field_name_camel] = 0.0
                    elif field.cpp_type == field.CPPTYPE_BOOL:
                        result[field_name_camel] = False
                    elif field.cpp_type == field.CPPTYPE_STRING:
                        result[field_name_camel] = ""
                    else:
                        result[field_name_camel] = None
                
                # Ensure field is added (should already be added above, but double-check)
                if field_name_camel not in result:
                    # This should never happen, but ensure it's added
                    if field.cpp_type in [field.CPPTYPE_INT32, field.CPPTYPE_INT64,
                                          field.CPPTYPE_UINT32, field.CPPTYPE_UINT64]:
                        result[field_name_camel] = 0
                    elif field.cpp_type in [field.CPPTYPE_DOUBLE, field.CPPTYPE_FLOAT]:
                        result[field_name_camel] = 0.0
                    elif field.cpp_type == field.CPPTYPE_BOOL:
                        result[field_name_camel] = False
                    elif field.cpp_type == field.CPPTYPE_STRING:
                        result[field_name_camel] = ""
                    else:
                        result[field_name_camel] = None
        except Exception:
            # If ANYTHING fails, still add the field with appropriate default
            if field.is_repeated():
                result[field_name_camel] = []
            elif field.message_type:
                result[field_name_camel] = {}
            else:
                if field.cpp_type in [field.CPPTYPE_INT32, field.CPPTYPE_INT64,
                                      field.CPPTYPE_UINT32, field.CPPTYPE_UINT64]:
                    result[field_name_camel] = 0
                elif field.cpp_type in [field.CPPTYPE_DOUBLE, field.CPPTYPE_FLOAT]:
                    result[field_name_camel] = 0.0
                elif field.cpp_type == field.CPPTYPE_BOOL:
                    result[field_name_camel] = False
                elif field.cpp_type == field.CPPTYPE_STRING:
                    result[field_name_camel] = ""
                else:
                    result[field_name_camel] = None
        
        # Final check: ensure field is ALWAYS in result
        if field_name_camel not in result:
            if field.is_repeated():
                result[field_name_camel] = []
            elif field.message_type:
                result[field_name_camel] = {}
            else:
                result[field_name_camel] = None
    
    return result

async def get_access_token(account):
    """Retrieve an access token for the given account."""
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(url, data=payload, headers=headers, timeout=30)
            if response.status_code != 200:
                return "0", "0"
            try:
                data = response.json()
            except:
                # If response is not JSON, return error
                return "0", "0"
            access_token = data.get("access_token", "0")
            open_id = data.get("open_id", "0")
            return access_token, open_id
        except Exception as e:
            return "0", "0"

async def create_jwt(region: str):
    """Create a JWT token for authentication."""
    account = ACCOUNTS.get(region.upper())
    if not account:
        return None, None, None
    
    access_token, open_id = await get_access_token(account)
    if access_token == "0" or open_id == "0":
        return None, None, None
    
    json_data = json.dumps({
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": access_token,
        "orign_platform_type": "4"
    })
    encoded_result = await json_to_proto(json_data, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, encoded_result)
    
    # Use only the working URL
    url = "https://loginbp.ggpolarbear.com/MajorLogin"
    
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(url, data=payload, headers=headers, timeout=30)
            if response.status_code != 200:
                return None, None, None
            
            # Check if response has content
            response_content = response.content
            if not response_content or len(response_content) == 0:
                return None, None, None
            
            # Try parsing directly first (response appears to be unencrypted)
            # If that fails, try decryption
            try:
                # Check if content length is valid for protobuf
                if len(response_content) < 4:
                    return None, None, None
                # Try parsing directly (response is likely not encrypted)
                login_res = decode_protobuf(response_content, FreeFire_pb2.LoginRes)
                message = json.loads(json_format.MessageToJson(login_res))
                lock_region = message.get("lockRegion") or message.get("lock_region", "0")
                server_url = message.get("serverUrl") or message.get("server_url", "0")
                token = message.get('token', '0')
                if token != '0' and server_url != "0":
                    return f"Bearer {token}", lock_region, server_url
            except Exception as parse_error:
                # If direct parsing fails, try decryption (in case response is encrypted)
                try:
                    # Only try decryption if content length is multiple of 16 (AES block size)
                    if len(response_content) % 16 == 0:
                        decrypted_data = aes_cbc_decrypt(MAIN_KEY, MAIN_IV, response_content)
                        login_res = decode_protobuf(decrypted_data, FreeFire_pb2.LoginRes)
                        message = json.loads(json_format.MessageToJson(login_res))
                        lock_region = message.get("lockRegion") or message.get("lock_region", "0")
                        server_url = message.get("serverUrl") or message.get("server_url", "0")
                        token = message.get('token', '0')
                        if token != '0' and server_url != "0":
                            return f"Bearer {token}", lock_region, server_url
                except Exception as decrypt_error:
                    pass
        except Exception as e:
            pass
    
    return None, None, None

async def GetAccountInformation(ID, UNKNOWN_ID, regionMain, endpoint):
    """
    Fetch account information from the specified endpoint.
    
    Args:
        ID (str): User ID.
        UNKNOWN_ID (str): Secondary ID (set to "7" in this case).
        regionMain (str): Region code.
        endpoint (str): API endpoint (e.g., "/GetPlayerPersonalShow").
    
    Returns:
        dict: Parsed response data or an error dictionary.
    """
    json_data = json.dumps({"a": ID, "b": UNKNOWN_ID})
    encoded_result = await json_to_proto(json_data, main_pb2.GetPlayerPersonalShow())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, encoded_result)
    
    regionMain = regionMain.upper()
    if regionMain not in SUPPORTED_REGIONS:
        return {"error": "Unsupported region", "message": f"Supported regions: {', '.join(SUPPORTED_REGIONS)}"}
    
    token, region, serverUrl = await create_jwt(regionMain)
    if not token or not serverUrl or serverUrl == "0":
        return {"error": "Authentication failed", "message": "Could not generate JWT"}
    
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Authorization': token,
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(serverUrl + endpoint, data=payload, headers=headers)
        # httpx automatically handles gzip decompression, but get raw content
        response_content = response.content
        message_type = AccountPersonalShow_pb2.AccountPersonalShowInfo  # Correct type for GetPlayerPersonalShow
        try:
            # Try parsing directly first (response is likely not encrypted)
            try:
                if len(response_content) < 4:
                    raise Exception("Response too short to be valid protobuf")
                decoded_message = decode_protobuf(response_content, message_type)
                # Use our custom function to get ALL fields
                try:
                    message = protobuf_to_dict_complete(decoded_message)
                except Exception as custom_error:
                    # Fallback to MessageToDict if custom function fails
                    try:
                        # Try with all options first
                        message = json_format.MessageToDict(
                            decoded_message,
                            including_default_value_fields=True,
                            preserving_proto_field_name=True,
                            use_integers_for_enums=True
                        )
                    except TypeError:
                        # Fallback: try with fewer options
                        try:
                            message = json_format.MessageToDict(decoded_message, use_integers_for_enums=True)
                        except TypeError:
                            # Simplest fallback - get all available fields
                            message = json_format.MessageToDict(decoded_message)
                    
                    # Also get the raw JSON format which might have more info
                    try:
                        raw_json = json.loads(json_format.MessageToJson(decoded_message))
                        # Merge any additional fields from raw_json that might be missing
                        if isinstance(raw_json, dict) and isinstance(message, dict):
                            # Add any missing keys from raw_json
                            for key, value in raw_json.items():
                                if key not in message:
                                    message[key] = value
                    except:
                        pass  # If this fails, just use the dict version
            except Exception as parse_error:
                # If direct parsing fails, try decryption (in case response is encrypted)
                try:
                    if len(response_content) % 16 == 0:
                        decrypted_content = aes_cbc_decrypt(MAIN_KEY, MAIN_IV, response_content)
                        decoded_message = decode_protobuf(decrypted_content, message_type)
                        try:
                            message = protobuf_to_dict_complete(decoded_message)
                        except Exception:
                            # Fallback to MessageToDict
                            try:
                                message = json_format.MessageToDict(
                                    decoded_message,
                                    including_default_value_fields=True,
                                    preserving_proto_field_name=True,
                                    use_integers_for_enums=True
                                )
                            except TypeError:
                                try:
                                    message = json_format.MessageToDict(decoded_message, use_integers_for_enums=True)
                                except TypeError:
                                    message = json_format.MessageToDict(decoded_message)
                    else:
                        # Return more detailed error
                        raise Exception(f"Direct parse failed: {str(parse_error)}, response length: {len(response_content)}, not multiple of 16")
                except Exception as decrypt_error:
                    raise Exception(f"Both parsing methods failed. Parse error: {str(parse_error)}, Decrypt error: {str(decrypt_error)}")
            return message
        except Exception as e:
            return {"error": "Failed to parse response", "details": str(e), "response_length": len(response_content), "response_preview": response_content[:50].hex() if len(response_content) > 0 else "empty"}