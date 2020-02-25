
class AdalRequestsSession:
    def __init__(self, conf):
        self.conf=conf
        print("Hello world from AdalRequestsSession")

    def get(self, url):
        print(f"GET {url}")
