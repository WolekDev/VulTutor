import re
from marshmallow import Schema, fields, validate, validates_schema, ValidationError


class LoginSchema(Schema):
    username = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=255),
        error_messages={"required": "username is required"},
    )
    password = fields.Str(
        required=True,
        validate=validate.Length(min=1),
        error_messages={"required": "password is required"},
    )


class RegisterSchema(Schema):
    username = fields.Str(
        required=True,
        validate=validate.Length(min=3, max=255),
        error_messages={"required": "username is required"},
    )
    email = fields.Email(
        required=True,
        error_messages={"required": "email is required", "validator_failed": "invalid email format"},
    )
    password = fields.Str(
        required=True,
        validate=validate.Length(min=8),
        error_messages={"required": "password is required"},
    )


class AnswerSchema(Schema):
    answer = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=1000),
        error_messages={"required": "answer is required"},
    )


class FlagSchema(Schema):
    flag = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=500),
        error_messages={"required": "flag is required"},
    )


class AccountUpdateSchema(Schema):
    username = fields.Str(validate=validate.Length(min=3, max=255), load_default=None)
    email = fields.Email(load_default=None)
    password = fields.Str(validate=validate.Length(min=8), load_default=None)

    @validates_schema
    def validate_at_least_one(self, data, **kwargs):
        if not any(data.get(f) for f in ("username", "email", "password")):
            raise ValidationError(
                "At least one field (username, email, password) must be provided"
            )


CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
