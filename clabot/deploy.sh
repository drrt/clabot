#!/bin/bash

# hack for homebrew python/pip
cat << _EOF > setup.cfg
[install]
prefix=
_EOF

pip install --target lib --requirement requirements.txt

rm setup.cfg

gcloud app deploy app.yaml --project feisty-reality-178421
