import html

# Idea inherited from what I heard about some other similar thing.

# NOTE: This is only safe as content like this: <div>here</div>.
# https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet#Why_Can.27t_I_Just_HTML_Entity_Encode_Untrusted_Data.3F

class HtmlSafe(object):
    def __init__(self):
        super().__init__()

    def __init__(self, val, val_is_already_safe=False):
        super().__init__()

        if type(val) is not str:
            raise TypeError()

        self._str = val if val_is_already_safe else html.escape(val)

    def __add__(self, val):
        if isinstance(val, HtmlSafe):
            return HtmlSafe(self._str + val._str, True)
        else:
            return HtmlSafe(self._str + html.escape(val), True)

    def __str__(self):
        return self._str
