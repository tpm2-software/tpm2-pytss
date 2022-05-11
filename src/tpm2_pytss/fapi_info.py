# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2020 Johannes Holland
# All rights reserved.

"""Interface to make TPM info dict structure more accessible via dot notation."""

from collections import defaultdict


class Traversable:
    """Attributes are traversable recursively."""

    def __init__(self, data):
        self.data = data

    def __str__(self):
        return str(self.data)

    def attrs_recursive(self, parent=""):
        """Return a generator to all attributes."""
        attrs_rec = []
        sep = "." if parent else ""

        for attr in dir(self):
            attr = attr.replace("-", "_")
            child = getattr(self, attr)
            if isinstance(child, Traversable):
                attrs_rec.extend(child.attrs_recursive(parent=f"{parent}{sep}{attr}"))
            else:
                attrs_rec.append(f"{parent}{sep}{attr}")

        yield from attrs_rec


class BasicDict(Traversable):
    """Takes a dict and makes values accessible via dot notation."""

    def __getattr__(self, attr):
        return self.data[attr]

    def __dir__(self):
        return self.data.keys()


class NamedKVPList(Traversable):
    """
    Takes a list of KVPs where both key and value are named (i.e. KVPs itself),
    e.g.
    [
        {
            "property": "VENDOR_TPM_TYPE",
            "value": 1
        },
        {
            "property": "FIRMWARE_VERSION_1",
            "value": 538513443
        }
    ]
    Makes the values accessible via dot notation. If a value_class is given, an
    instance of that class is returned (passing the value to __init__()).
    """

    def __init__(self, data, key_name, value_name, value_class=None):
        super().__init__(data)
        self.key_name = key_name
        self.value_name = value_name
        self.value_class = value_class

    def __getattr__(self, attr):
        value = next(
            item[self.value_name]
            for item in self.data
            if item[self.key_name].lower() == attr.lower()
        )

        if self.value_class:
            return self.value_class(value)

        return value

    def __dir__(self):
        return [item[self.key_name].lower() for item in self.data]


class Capabilities(Traversable):
    """Takes a list of capability dicts and makes them accessible via dot notation."""

    def _get_cap_data(self, description):
        return next(cap for cap in self.data if cap["description"] == description)[
            "info"
        ]["data"]

    def __getattr__(self, attr):
        # some caps are accessed via '_' but their names contain '-'
        attr = attr.replace("_", "-")
        cap_data = self._get_cap_data(attr)

        cap = defaultdict(
            lambda: cap_data,
            {
                "algorithms": NamedKVPList(
                    cap_data, "alg", "algProperties", value_class=globals()["BasicDict"]
                ),
                "properties-fixed": NamedKVPList(cap_data, "property", "value"),
                "properties-variable": NamedKVPList(cap_data, "property", "value"),
                "commands": None,  # TODO by command index?
                "pcrs": NamedKVPList(cap_data, "hash", "pcrSelect"),
                "pcr-properties": NamedKVPList(cap_data, "tag", "pcrSelect"),
            },
        )[attr]

        return cap

    def __dir__(self):
        return [item["description"] for item in self.data]


def str_from_int_list(int_list):
    """Cast integers to bytes and decode as string."""
    string = b"".join(
        integer.to_bytes(4, byteorder="big") for integer in int_list
    ).decode("utf-8")
    # remove leading or trailing whitespaces
    string = string.strip()
    # remove null bytes
    string = string.replace("\x00", "")
    # replace multiple whitespaces with a single one
    string = " ".join(string.split())

    return string


class FapiInfo(Traversable):
    """Takes a FAPI info dict and and makes its values accessible via dot notation."""

    def __getattr__(self, attr):
        item_data = self.data[attr]

        return defaultdict(
            lambda: item_data,
            {
                "fapi_config": BasicDict(item_data),
                "capabilities": Capabilities(item_data),
            },
        )[attr]

    @property
    def vendor_string(self):
        """Get the TPM Vendor String."""
        return str_from_int_list(
            [
                self.capabilities.properties_fixed.vendor_string_1,
                self.capabilities.properties_fixed.vendor_string_2,
                self.capabilities.properties_fixed.vendor_string_3,
                self.capabilities.properties_fixed.vendor_string_4,
            ]
        )

    @property
    def manufacturer(self):
        """Get the TPM Manufacturer."""
        return str_from_int_list([self.capabilities.properties_fixed.manufacturer])

    @property
    def firmware_version(self):
        """Get the TPM Firmware Version (formatted according to vendor conventions)."""
        key = f"{self.manufacturer}.{self.vendor_string}"
        ver1 = self.capabilities.properties_fixed.firmware_version_1
        ver2 = self.capabilities.properties_fixed.firmware_version_2

        return defaultdict(
            lambda: f"{ver1:x}.{ver2:x}", {"IBM.SW TPM": f"{ver1:x}.{ver2:x}"}
        )[key]

    @property
    def spec_revision(self):
        """Get the TPM Specification Revision."""
        rev = self.capabilities.properties_fixed.ps_revision
        # Add '.' after first digit
        rev = f"{rev // 100}.{rev % 100}"

        return rev

    def __dir__(self):
        return self.data.keys()
