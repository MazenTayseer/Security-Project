class Constants:
    SHARED_FOLDER = "shared"

    @staticmethod
    def credentials_file(port):
        return f"credentials_{port}.enc"