#  Copyright 2023 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from pydantic import BaseModel as PydanticBaseModel, Extra
from pydantic.generics import GenericModel as PydanticGenericModel


class BaseModel(PydanticBaseModel):
    """Substitute for pydantic's BaseModel.
    This class defines a project BaseModel to be used instead of pydantic's, setting stricter global configurations.
    Other configurations can be set on a case by case basis.

    Read: https://docs.pydantic.dev/usage/model_config/#change-behaviour-globally
    """

    def json_dumpb(self) -> bytes:
        """Utility method for converting a Model into bytes representation of a JSON."""
        from hathor.util import json_dumpb
        return json_dumpb(self.dict())

    class Config:
        allow_mutation = False
        extra = Extra.forbid


class GenericModel(BaseModel, PydanticGenericModel):
    """Substitute for pydantic's GenericModel.
    This class defines a project GenericModel to be used instead of pydantic's, setting stricter global configurations.
    Other configurations can be set on a case by case basis.

    Read: https://docs.pydantic.dev/usage/model_config/#change-behaviour-globally
    """
    pass
