"""ESolar Cloud Platform data fetchers."""
import datetime
import hashlib
import logging
import random
import string

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from requests import HTTPError, Timeout, RequestException

_LOGGER = logging.getLogger(__name__)

WEB_TIMEOUT = 10

BASIC_TEST = False
VERBOSE_DEBUG = False
if BASIC_TEST:
    from .esolar_static_test import (
        get_esolar_data_static_h1_r5,
        web_get_plant_static_h1_r5,
    )


def base_url_web(region):
    if region == "eu":
        return "https://eop.saj-electric.com/dev-api/api/v1"
    elif region == "in":
        return "https://iop.saj-electric.com/dev-api/api/v1"
    elif region == "cn":
        return "https://op.saj-electric.com/dev-api/api/v1"
    else:
        raise ValueError("Region not set. Please run Configure again")


def get_esolar_data(region, username, password, plant_list=None,
    use_pv_grid_attributes=True):
    """SAJ eSolar Data Update."""
    if BASIC_TEST:
        return get_esolar_data_static_h1_r5(
            region, username, password, plant_list, use_pv_grid_attributes
        )

    token = esolar_web_authenticate(region, username, password)
    plant_info = web_get_plant_list(region, token, plant_list)
    web_get_plant_info(region, token, plant_info)
    web_get_plant_grid_overview_info(region, token, plant_info)
    # TODO: Needs to be determined if this is still relevant. Not sure what it needs to do
    # web_get_device_page_list(region, token, plant_info,
    #                          use_pv_grid_attributes)

    return plant_info


def encrypt_password(password,
    encryption_key="ec1840a7c53cf0709eb784be480379b6"):
    """Encrypt the password using AES-128-CBC. The key is hardcoded and can be found in the web portal."""
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(password.encode()) + padder.finalize()

    # Create cipher
    cipher = Cipher(
        algorithms.AES(bytes.fromhex(encryption_key)),
        modes.ECB(),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    return (encryptor.update(padded_data) + encryptor.finalize()).hex()


def generate_signature(params: dict[str, int | str],
    signing_key="ktoKRLgQPjvNyUZO8lVc9kU1Bsip6XIe"):
    """Generate the signature for the API request. The signing key is hardcoded and can be found in the web portal."""
    output = '&'.join(f"{k}={v}" for k, v in sorted(params.items()))
    output += f"&key={signing_key}"
    md5 = hashlib.md5(output.encode()).hexdigest()
    return hashlib.sha1(md5.encode()).hexdigest().upper()


def generate_random(length=32):
    characters = string.ascii_letters + string.digits  # combines uppercase, lowercase and numbers
    return ''.join(random.choice(characters) for _ in range(length))


def esolar_web_authenticate(region, username, password):
    """Authenticate the user to the SAJ's WEB Portal."""
    if BASIC_TEST:
        return True

    session = requests.Session()
    lang = "en"
    project_name = "elekeeper"
    client_id = "esolar-monitor-admin"
    client_date = "2025-07-06"
    timestamp = int(datetime.datetime.now().timestamp() * 1000)
    rnd = generate_random()

    response = session.post(
        base_url_web(region) + "/sys/login",
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json",
                 "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.3"},
        data={
            "lang": lang,
            "username": username,
            "password": encrypt_password(password),
            "rememberMe": "false",
            "loginType": "1",
            "appProjectName": project_name,
            "random": rnd,
            "clientDate": client_date,
            "timeStamp": timestamp,
            "clientId": client_id,
            "signParams": "appProjectName,clientDate,lang,timeStamp,random,clientId",
            "signature": generate_signature({"appProjectName": project_name,
                                             "clientDate": client_date,
                                             "clientId": client_id,
                                             "lang": lang,
                                             "random": rnd,
                                             "timeStamp": timestamp}),
        },
        timeout=WEB_TIMEOUT,
    )

    try:
        response.raise_for_status()
        return response.json()["data"]["token"]
    except:
        raise ValueError(response.content)


def web_get_plant_list(region, token, requested_plant_list=None):
    """Retrieve the platUid from WEB Portal using web_authenticate."""
    if token is None:
        raise ValueError("Missing token trying to obtain plants")

    if BASIC_TEST:
        return web_get_plant_static_h1_r5()

    output_plant_list = []
    session = requests.Session()
    page_size = 100
    lang = "en"
    project_name = "elekeeper"
    client_id = "esolar-monitor-admin"
    client_date = "2025-07-07"
    timestamp = int(datetime.datetime.now().timestamp() * 1000)
    rnd = generate_random()
    sign_params = "pageSize,pageNo,searchOfficeIdArr,appProjectName,clientDate,lang,timeStamp,random,clientId"

    response = session.get(
        base_url_web(region) + "/monitor/plant/getPlantList",
        headers={"Authorization": "Bearer " + token,
                 "Accept": "application/json",
                 "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.3"},
        params={
            "pageSize": page_size,
            "pageNo": 1,
            "searchOfficeIdArr": 1,
            "appProjectName": project_name,
            "clientDate": client_date,
            "lang": lang,
            "timeStamp": timestamp,
            "random": rnd,
            "clientId": client_id,
            "signParams": sign_params,
            "signature": generate_signature({
                "pageSize": page_size,
                "pageNo": 1,
                "searchOfficeIdArr": 1,
                "appProjectName": project_name,
                "clientDate": client_date,
                "clientId": client_id,
                "lang": lang,
                "random": rnd,
                "timeStamp": timestamp}),
        },
        timeout=WEB_TIMEOUT,
    )

    try:
        response.raise_for_status()
        plant_list = response.json()["data"]["list"]
        if requested_plant_list is not None:
            for plant in plant_list:
                if plant["plantName"] in requested_plant_list:
                    output_plant_list.append(plant)
            return {"status": plant_list["status"],
                    "plantList": output_plant_list}
        return plant_list
    except:
        raise ValueError(response.content)


def web_get_plant_info(region, token, plants):
    """Retrieve platUid from the WEB Portal using web_authenticate."""
    if token is None:
        raise ValueError("Missing token trying to obtain plant details")

    try:
        for plant in plants:
            plant_uid = plant["plantUid"]
            lang = "en"
            project_name = "elekeeper"
            client_id = "esolar-monitor-admin"
            client_date = "2025-07-07"
            timestamp = int(datetime.datetime.now().timestamp() * 1000)
            rnd = generate_random()
            sign_params = "plantUid,appProjectName,clientDate,lang,timeStamp,random,clientId"

            session = requests.Session()
            response = session.get(
                base_url_web(region) + "/monitor/plant/getOnePlantInfo",
                headers={"Authorization": "Bearer " + token,
                         "Accept": "application/json",
                         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.3"},
                params={
                    "plantUid": plant_uid,
                    "appProjectName": project_name,
                    "clientId": client_id,
                    "clientDate": client_date,
                    "lang": lang,
                    "timeStamp": timestamp,
                    "random": rnd,
                    "signParams": sign_params,
                    "signature": generate_signature({
                        "plantUid": plant_uid,
                        "appProjectName": project_name,
                        "clientDate": client_date,
                        "clientId": client_id,
                        "lang": lang,
                        "timeStamp": timestamp,
                        "random": rnd
                    })
                },
                timeout=WEB_TIMEOUT,
            )

            try:
                response.raise_for_status()
                plant_detail = response.json()["data"]
                plant.update(plant_detail)
            except:
                raise ValueError(response.content)

    except HTTPError as errh:
        raise HTTPError(errh)
    except ConnectionError as errc:
        raise ConnectionError(errc)
    except Timeout as errt:
        raise Timeout(errt)
    except RequestException as errr:
        raise RequestException(errr)


def web_get_plant_grid_overview_info(region, token, plants):
    """Retrieve the kitList from the WEB Portal with web_authenticate."""
    if token is None:
        raise ValueError("Missing token trying to obtain plants")

    for plant in plants:
        # bean = []
        peak_pow = []
        for inverter in plant["deviceSnList"]:
            plant_uid = plant["plantUid"]
            lang = "en"
            project_name = "elekeeper"
            client_id = "esolar-monitor-admin"
            client_date = "2025-07-07"
            refresh = int(datetime.datetime.now().timestamp() * 1000)
            timestamp = int(datetime.datetime.now().timestamp() * 1000)
            rnd = generate_random()
            sign_params = "plantUid,refresh,appProjectName,clientDate,lang,timeStamp,random,clientId"

            session = requests.Session()
            response = session.get(
                base_url_web(
                    region) + "/monitor/home/getPlantGridOverviewInfo",
                headers={"Authorization": "Bearer " + token,
                         "Accept": "application/json",
                         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.3"},
                params={
                    "plantUid": plant_uid,
                    "appProjectName": project_name,
                    "clientId": client_id,
                    "clientDate": client_date,
                    "lang": lang,
                    "refresh": refresh,
                    "random": rnd,
                    "timeStamp": timestamp,
                    "signParams": sign_params,
                    "signature": generate_signature({
                        "plantUid": plant_uid,
                        "appProjectName": project_name,
                        "clientDate": client_date,
                        "clientId": client_id,
                        "lang": lang,
                        "timeStamp": timestamp,
                        "refresh": refresh,
                        "random": rnd
                    })
                },
                timeout=WEB_TIMEOUT,
            )

            try:
                response.raise_for_status()
                overview_info = response.json()["data"]

                if VERBOSE_DEBUG:
                    _LOGGER.debug(
                        "\n.../getPlantGridOverviewInfo\n------------------------\n%s",
                        overview_info,
                    )
                # if (overview_info["type"]) == 0:
                peak_pow.append({
                    "devicesn": inverter,
                    "peakPower": overview_info["peakPower"]
                })
                plant.update({"peakList": peak_pow})
                # TODO: Not sure how to fix this and if this is (still) relevant
                # elif (overview_info["type"]) == 1:
                #     overview_info["viewBean"].update({"devicesn": inverter})
                #     bean.append(overview_info["viewBean"])
                #     plant.update({"beanList": bean})
            except:
                raise ValueError(response.content)


def web_get_device_page_list(region, token, plants,
    use_pv_grid_attributes):
    """Retrieve the plantUid from the WEB Portal with web_authenticate."""
    if token is None:
        raise ValueError("Missing token trying to obtain plants")

    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    }

    try:
        for plant in plants:
            _LOGGER.debug("Plant UID: %s", plant["plantUid"])
            _LOGGER.debug("Plant Type: %s", plant["type"])

            chart_month = datetime.date.today().strftime("%Y-%m")
            url = f"{base_url_web(region)}/cloudMonitor/device/findDevicePageList"
            payload = f"officeId=1&pageNo=&pageSize=&orderName=1&orderType=2&plantuid={plant['plantUid']}&deviceStatus=&localDate={datetime.date.today().strftime('%Y-%m-%d')}&localMonth={chart_month}"
            _LOGGER.debug("Fetching URL    : %s", url)
            _LOGGER.debug("Fetching Payload: %s", payload)
            session = requests.Session()
            response = session.post(
                url, headers=headers, data=payload, timeout=WEB_TIMEOUT
            )
            response.raise_for_status()
            device_list = response.json()["list"]
            if VERBOSE_DEBUG:
                _LOGGER.debug(
                    "\n.../findDevicePageList\n----------------------\n%s",
                    device_list
                )

            kit = []
            for device in device_list:
                if not device["devicesn"] in plant["plantDetail"]["snList"]:
                    continue
                _LOGGER.debug("Device SN: %s", device["devicesn"])
                if use_pv_grid_attributes:
                    url = f"{base_url_web(region)}/cloudMonitor/deviceInfo/findRawdataPageList"
                    payload = f"deviceSn={device['devicesn']}&deviceType={device['type']}&timeStr={datetime.date.today().strftime('%Y-%m-%d')}"
                    _LOGGER.debug("Fetching URL    : %s", url)
                    _LOGGER.debug("Fetching Payload: %s", payload)
                    response = session.post(
                        url, headers=headers, data=payload, timeout=WEB_TIMEOUT
                    )
                    response.raise_for_status()
                    find_rawdata_page_list = response.json()
                    _LOGGER.debug(
                        "Result length   : %s",
                        len(find_rawdata_page_list["list"])
                    )

                    if len(find_rawdata_page_list["list"]) > 0:
                        device.update(
                            {"findRawdataPageList":
                                 find_rawdata_page_list["list"][0]}
                        )
                    else:
                        device.update({"findRawdataPageList": None})

                    if VERBOSE_DEBUG and len(
                        find_rawdata_page_list["list"]) > 0:
                        _LOGGER.debug(
                            "\n.../findRawdataPageList\n-----------------------\n%s",
                            find_rawdata_page_list["list"][0],
                        )

                # Fetch battery for H1 system (UNTESTED CODE)
                if plant["type"] == 3:
                    _LOGGER.debug("Fetching storage information")
                    epochmilliseconds = datetime.datetime.now().timestamp() * 1000
                    url = f"{base_url_web(region)}/monitor/site/getStoreOrAcDevicePowerInfo"
                    payload = f"plantuid={plant['plantuid']}&devicesn={device['devicesn']}&_={epochmilliseconds}"
                    _LOGGER.debug("Fetching URL    : %s", url)
                    _LOGGER.debug("Fetching Payload: %s", payload)
                    response = session.post(
                        url, headers=headers, data=payload, timeout=WEB_TIMEOUT
                    )
                    response.raise_for_status()
                    store_device_power = response.json()
                    device.update(store_device_power)
                    if VERBOSE_DEBUG:
                        _LOGGER.debug(
                            "getStoreOrAcDevicePowerInfo\n-------------------------------\n%s",
                            store_device_power,
                        )

                kit.append(device)

            plant.update({"kitList": kit})

    except HTTPError as errh:
        raise HTTPError(errh)
    except ConnectionError as errc:
        raise ConnectionError(errc)
    except Timeout as errt:
        raise Timeout(errt)
    except RequestException as errr:
        raise RequestException(errr)
