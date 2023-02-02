from pydantic import BaseModel as PydanticBaseModel, Extra
from pydantic.generics import GenericModel as PydanticGenericModel


class BaseModel(PydanticBaseModel):
    class Config:
        allow_mutation = False
        extra = Extra.forbid


class GenericModel(PydanticGenericModel):
    class Config:
        allow_mutation = False
        extra = Extra.forbid
