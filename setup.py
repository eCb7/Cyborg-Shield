from setuptools import setup, find_packages

setup(
    name="cyborg-shield",
    version="1.0.0",
    description="Le Bouclier Cyborg — pare-feu pédagogique (Teen Titans)",
    packages=find_packages(),
    install_requires=["click>=8.1", "rich>=13.0"],
    entry_points={
        "console_scripts": [
            "cyborg-shield=cyborg_shield.main:cli",
        ]
    },
    python_requires=">=3.10",
)
