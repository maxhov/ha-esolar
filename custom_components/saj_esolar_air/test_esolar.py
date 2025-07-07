import unittest

from custom_components.saj_esolar_air.esolar import get_esolar_data, \
    generate_signature, encrypt_password


class TestGetEsolarData(unittest.TestCase):

    def test_get_esolar_data_success(self):
        region = "eu"
        username = "user"
        password = "password"
        result = get_esolar_data(region, username, password)
        self.assertIsNotNone(result)


    def test_verify_hash(self):
        password = "passwd"
        encrypted_password = encrypt_password(password)
        self.assertEqual(encrypted_password, "a8055cb2a374c3d0f44d95c36d90073a")


    def test_signature(self):
        data = {
            "appProjectName": "elekeeper",
            "clientDate": "2025-07-06",
            "clientId": "esolar-monitor-admin",
            "lang": "en",
            "random": "BGZWCi5XnfCkxw2X2Gw8y364QBkm6636",
            "timeStamp": "1751834849930"
        }
        signature = generate_signature(data)
        self.assertEqual(signature, "4E0F8614295B5D4802DAE4D0ED8AFA2EB70F09D1")

if __name__ == "__main__":
    unittest.main()
