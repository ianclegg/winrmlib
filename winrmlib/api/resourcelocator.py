from suds.sax.element import Element
from suds.sax.attribute import Attribute


class ResourceLocator(object):
    """
    Resource Locator
    TO DO, constructor should accept a dictionary of options and a dictionary of list for selectors
    """

    def __init__(self, url):
        self.url = url
        self.options = {}
        self.selectors = {}

    def add_option(self, name, value, must_comply):
        self.options[name] = [value, must_comply]

    def clear_options(self):
        self.options = {}

    def add_selector(self, name, value):
        self.selectors[name] = value

    def clear_selectors(self):
        self.selectors = {}