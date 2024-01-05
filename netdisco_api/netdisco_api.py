"""
A wrapper for the webservice (REST API) for Netdisco.
"""

import atexit
import requests
from requests.auth import HTTPBasicAuth
import json

# Delete TLS warning
requests.packages.urllib3.disable_warnings()

class NetdiscoAPI:
    def __init__(
        self,
        host,
        user,
        password,
        verify_cert=True,
        login=True,
        enforce_encryption=True,
    ):
        """
        Log in to Netdisco Web service (Request a session ID)

        Args:
            host: The address of the netdisco server host including protocol (https://)
            user: The name of the netdisco user to log in as
            password: The password of the netdisco user
            verify_cert: Verify server certificate (Default: True).
            login: Automatically log in on object instantiation (Default: True)
            enforce_encryption: Raise an exception if traffic is unencrypted (Not https:// in host)
        """

        # Must encrypt traffic
        if "https://" not in host and enforce_encryption:
            raise ValueError("Unencrypted host not allowed: {host}")

        # The session to use for all requests
        self._session = requests.Session()

        # The URL of the Netdisco server
        self._url = f"{host}"

        # Log in to get this ID from Netdisco
        self._session_id = None

        # Pass to requests
        self._verify_cert = verify_cert

        # root request
        self._root_uri = "api/v1/"

        # Automatic logout
        atexit.register(self.logout)

        # Login to Netdisco (Get a session_id)
        if login:
           self.login(user, password)

    def login(self, user, password):
        """
        Login to Netdisco by getting a session ID to include in posts

        Args:
            user (str): The username to login as
            password (str): The password of the user

        Returns:
            Session id (str)
        """
       
        auth = HTTPBasicAuth(user, password)
        json_token = self._post(auth, None, 'login')
        self._session_id = json.loads(json_token)['api_key']
        return self._session_id

    def logout(self):
        """
        Log out of Netdisco. Deletes session ID       
        """

        self._get('logout')
        self._session_id = None

    def _get(self, uri, payload=None):
        """
        Receive data from the Netdisco server

        Args:
            uri: URI build
            payload: data (Default: None)

        Returns:
            result: The content of the data in JSON format returned by the server
        """

        # build headers based on custom and permanent headers
        headers={}
        headers_dialog={'accept': 'application/json'}
        headers_auth={'Authorization': self._session_id}
        headers.update(headers_auth)
        headers.update(headers_dialog)

        # http get
        r = self._session.get(self._url + uri, verify=self._verify_cert, headers=headers, params=payload)
        return r.json()

    def _post(self, auth, data, uri=''):
        """
        Send data to the NetDisco server

        Args:
            auth: Authentication informations (base64)
            data: The data to post
            uri (str): URI build

        Returns:
            result: The value of the key 'result' in the JSON returned by the server
        """

        # with REST api , url could change, so if url isn't specified we take main url (mainly for RPC method)
        url=self._url + uri

        # build headers based on custom and permanent headers
        headers={}
        headers_dialog={'accept': 'application/json'}
        headers.update(headers_dialog)

        # http post
        r = self._session.post(url, auth=auth, json=data, verify=self._verify_cert, headers=headers)
        # Raise exception on error codes
        #r.raise_for_status()
        # Get the json in the response
        #r = r.json()
        if r.status_code == 200 :
            return(r.text)
        else :
            print(r.text + "  " + str(r.status_code))
    
    # ----------------------------- Search Operations

    def search_device(self, payload):
        """
        Search device (like network component), following arguments could be used:

        Args (dict) :
            q (str): Partial match of Device contact, serial, module serials, location, name, description, dns, or any IP alias
            name (str): Partial match of the Device name
            location (str): Partial match of the Device location
            dns (str): Partial match of any of the Device IP aliases
            ip (str): IP or IP Prefix within which the Device must have an interface address
            description (str): Partial match of the Device description
            mac (str): MAC Address of the Device or any of its Interfaces
            model (str): Exact match of the Device model
            os (str): Exact match of the Device operating system
            os_ver (str): Exact match of the Device operating system version
            vendor (str): Exact match of the Device vendor
            layers (str): OSI Layer which the device must support
            matchall (bool): If true, all fields (except "q") must match the Device. Default value: false
            seeallcolumns (bool): If true, all columns of the Device will be shown. Default value: false

        Returns:
            result: Array value found
        """

        # Convert bool to str.lower()
        if 'matchall' in payload: payload['matchall'] = str(payload['matchall']).lower()
        if 'seeallcolumns' in payload: payload['seeallcolumns'] = str(payload['seeallcolumns']).lower()
        
        r=self._get(self._root_uri + 'search/device', payload=payload)
        return r
    
    def search_node(self, payload):
        """
        Search node (like computer / server all not a network management), following arguments could be used:

        Args (dict) :
            q (mandatory) (str): MAC Address or IP Address or Hostname (without Domain Suffix) of a Node (supports SQL or "*" wildcards)
            partial (bool): Partially match the "q" parameter (wildcard characters not required). Default value: false
            deviceports (bool): MAC Address search will include Device Port MACs. Default value: true
            show_vendor (bool): Include interface Vendor in results. Default value: false
            archived (bool): Include archived records in results. Default value: false
            daterange (str): Date Range in format "YYYY-MM-DD to YYYY-MM-DD". Default value: 1970-01-01 to current date
            age_invert (bool): Results should NOT be within daterange. Default value: false

        Returns:
            result: Array value found
        """

        # Default values
        final_payload = {
            'deviceports': 'true'
        }
        
        if 'q' in payload: final_payload['q'] = payload['q']

        # Convert bool to str.lower()
        if 'partial' in payload: final_payload['partial'] = str(payload['partial']).lower()
        if 'deviceports' in payload: final_payload['deviceports'] = str(payload['deviceports']).lower()
        if 'show_vendor' in payload: final_payload['show_vendor'] = str(payload['show_vendor']).lower()
        if 'archived' in payload: final_payload['archived'] = str(payload['archived']).lower()
        if 'age_invert' in payload: final_payload['age_invert'] = str(payload['age_invert']).lower()

        r=self._get(self._root_uri + 'search/node', payload=final_payload)
        return r

    def search_port(self, payload):
        """
        Search port (by MAC address or vlan), following arguments could be used:

        Args (dict) :
            q (mandatory) (str): Port name or VLAN or MAC address
            partial (bool): Search for a partial match on parameter "q". Default value: true
            uplink (bool): Include uplinks in results. Default value: false
            descr (bool): Search in the Port Description field. Default value: false
            ethernet (bool): Only Ethernet type interfaces in results. Default value: true
        Returns:
            result: Array value found
        """

        # Default values
        final_payload = {
            'partial': 'true',
            'ethernet': 'true'
        }
        
        if 'q' in payload: final_payload['q'] = payload['q']

        # Convert bool to str.lower()
        if 'partial' in payload: final_payload['partial'] = str(payload['partial']).lower()
        if 'uplink' in payload: final_payload['uplink'] = str(payload['uplink']).lower()
        if 'descr' in payload: final_payload['descr'] = str(payload['descr']).lower()
        if 'ethernet' in payload: final_payload['ethernet'] = str(payload['ethernet']).lower()

        r=self._get(self._root_uri + 'search/port', payload=final_payload)
        return r

    def search_vlan(self, payload):
        """
        Search vlan (by vlan), following arguments could be used:

        Args :
            q (mandatory) (str): VLAN name or number
        Returns:
            result: Array value found
        """

        r=self._get(self._root_uri + 'search/vlan', payload=payload)
        return r
    
    # ----------------------------- Objects Operations

    def object_device(self, ip=None):
        """
        Get device information by ip, following arguments could be used:

        Args :
            ip (mandatory) (str): Canonical IP of the Device. Use Search methods to find this.
        Returns:
            result: Array value found
        """

        r=self._get(self._root_uri + 'object/device/' + ip)
        return r

    def object_device_ips(self, ip=None):
        """
        Netdisco > Device > Addresses
        Returns device_ips rows for a given device, following arguments could be used:
        
        Args :
            ip (mandatory) (str): Canonical IP of the Device. Use Search methods to find this.
        Returns:
            result: Array value found
        """
        
        r=self._get(self._root_uri + 'object/device/' + ip + '/device_ips')
        return r
    
    def object_device_modules(self, ip=None):
        """
        Netdisco > Device > Modules
        Returns modules rows for a given device, following arguments could be used:
        
        Args :
            ip (mandatory) (str): Canonical IP of the Device. Use Search methods to find this.
        Returns:
            result: Array value found
        """
        
        r=self._get(self._root_uri + 'object/device/' + ip + '/modules')
        return r
    
    def object_device_neighbors(self, payload, ip=None):
        """
        Netdisco > Device > Neighbors
        Returns layer 2 neighbor relation data for a given device, following arguments could be used:
        
        Args :
            ip (mandatory) (str): Canonical IP of the Device. Use Search methods to find this.
            payload (dict): see following elements
                scope (str): Scope of results, either "all", "cloud" (LLDP cloud), or "depth" (uses hops). Default value: depth
                hops (str): When specifying Scope "depth", this is the number of hops. Default value: 1
                vlan (str): Limit results to devices carrying this numeric VLAN ID
        Returns:
            result: Array value found
        """
        
        r=self._get(self._root_uri + 'object/device/' + ip + '/neighbors', payload=payload)
        return r

    def object_device_nodes(self, payload, ip=None):
        """
        Returns the nodes found on a given Device, following arguments could be used:
        
        Args :
            ip (mandatory) (str): Canonical IP of the Device. Use Search methods to find this.
            payload (dict): see following elements
                active_only (bool): Restrict results to active Nodes only. Default value: True
        Returns:
            result: Array value found
        """

        # Default values
        final_payload = {
            'active_only': 'true'
        }
        
        # Convert bool to str.lower()
        if payload:
            if 'active_only' in payload: final_payload['active_only'] = str(payload['active_only']).lower()

        r=self._get(self._root_uri + 'object/device/' + ip + '/nodes', payload=final_payload)
        return r