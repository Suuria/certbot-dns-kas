from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="certbot-dns-kas",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="KAS DNS Authenticator plugin for Certbot",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/certbot-dns-kas",
    packages=find_packages(),
    python_requires=">=3.6",
    install_requires=[
        "certbot>=1.0.0",
        "requests>=2.20.0",
        "zope.interface",
    ],
    entry_points={
        "certbot.plugins": [
            "dns-kas = certbot_dns_kas.dns_kas:Authenticator",
        ],
    },
    include_package_data=True,
)