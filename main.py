import logging

from test.TSS2_BaseTest import TpmSimulator

from tpm2_pytss import FAPI, FapiConfig
from tpm2_pytss.log import tss_loggers

# highlight using ANSI color codes
green = "\x1b[32m"
yellow = "\x1b[93m"
red = "\x1b[31"
blue = "\x1b[34m"
cyan = "\x1b[96m"
light_grey = "\x1b[37m"
reset = "\x1b[0m"

# setup logging
root_logger = logging.getLogger()
root_logger.setLevel(logging.NOTSET)
handler = logging.StreamHandler()
formatter = logging.Formatter(
    f"{light_grey}[%(levelname)s]{reset} {blue}%(pathname)s:%(lineno)d{reset} - {cyan}%(name)s {yellow}%(message)s{reset}",
    "%Y-%m-%d %H:%M:%S",
)
handler.setFormatter(formatter)
root_logger.addHandler(handler)

# set some TSS log levels as an example
for _module, logger in tss_loggers.items():
    logger.setLevel(logging.WARNING)
logging.getLogger("TSS.fapijson").setLevel(logging.DEBUG)

if __name__ == "__main__":
    tpm = TpmSimulator.getSimulator()
    tpm.start()

    with FapiConfig(
        temp_dirs=True, tcti=tpm.tcti_name_conf, ek_cert_less="yes"
    ) as fapi_config:
        with FAPI() as fapi:
            fapi.provision()

            fapi.create_key(path=f"/{fapi.config.profile_name}/HS/SRK/key_123")

            # provoke error logs
            fapi.create_key(
                path=f"/{fapi.config.profile_name}/HS/SRK/key_123", exists_ok=True
            )

    tpm.close()
