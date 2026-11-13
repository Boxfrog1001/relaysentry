from setuptools import setup

setup(
    name="relaysentry",
    version="0.3.3",
    description="Privacy-preserving Tor relay DoS triage, consensus peer attribution & adaptive shield CLI",
    author="RelaySentry Contributors",
    license="BSD-2-Clause",
    package_dir={"": "src"},
    py_modules=[
        "relaysentry",
        "privacy_vault",
        "telemetry_procfs",
        "telemetry_tor",
        "consensus_index",
        "correlator",
        "shield_engine",
    ],
    scripts=["bin/relaysentry"],
    python_requires=">=3.10",
)
