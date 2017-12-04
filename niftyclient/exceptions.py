
class NiftyBaseError(Exception):
    pass


class ResponseError(NiftyBaseError):
    pass


class AuthenticationError(ResponseError):
    pass


class ResponseFormatError(ResponseError):
    pass
