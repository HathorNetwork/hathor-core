# encoding: utf-8

from collections import defaultdict
from enum import Enum


class HathorEvents(Enum):
    MANAGER_ON_START = 'manager:on_start'
    MANAGER_ON_STOP = 'manager:on_stop'


class EventArguments(object):
    """Simple object for storing event arguments.
    """
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __contains__(self, key):
        return key in self.__dict__


class PubSubManager(object):
    """Manages a pub/sub pattern bus.

    It is used to let independent objects respond to events.
    """
    def __init__(self):
        self._subscribers = defaultdict(list)

    def subscribe(self, key, fn):
        """Subscribe to a specific event.

        :param key: Name of the key to which to subscribe.
        :type key: string

        :param fn: A function to be called when an event with `key` is published.
        :type fn: function
        """
        if fn not in self._subscribers[key]:
            self._subscribers[key].append(fn)

    def unsubscribe(self, key, fn):
        """Unsubscribe from a specific event.
        """
        if fn in self._subscribers[key]:
            self._subscribers[key].pop(fn)

    def publish(self, key, **kwargs):
        """Publish a new event.

        :param key: Key of the new event.
        :type key: string

        :param **kwargs: Named arguments to be given to the functions that will be called with this event.
        :type **kwargs: dict
        """
        args = EventArguments(**kwargs)
        for fn in self._subscribers[key]:
            fn(key, args)
