from abc import abstractproperty, abstractmethod
from typing import Dict

from stp_core.types import Identifier

# TODO: move it to crypto repo


class Signer:
    """
    Interface that defines a sign method.
    """
    @abstractproperty
    def identifier(self) -> Identifier:
        raise NotImplementedError

    @abstractmethod
    def sign(self, msg: Dict) -> Dict:
        raise NotImplementedError

    @abstractproperty
    def alias(self) -> str:
        raise NotImplementedError


