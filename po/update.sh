#!/bin/sh
# Regenerate po/peekin.pot from the Rust sources and merge it into every
# translation. Run after changing user-visible text:  sh po/update.sh
set -eu
cd "$(dirname "$0")/.."
find crates/peekin-core/src crates/peekin-pam/src crates/peekin-settings/src crates/peekin-vision/src -name '*.rs' ! -name i18n.rs | sort > po/POTFILES
xgettext --language=Rust --from-code=UTF-8 --add-comments=TRANSLATORS --no-location --no-wrap \
    --keyword=tr:1 --keyword=tr_args:1 --keyword=trn:1,2 --keyword=tr_noop:1 \
    --package-name=peekin --msgid-bugs-address=info@chrisdaggas.com \
    --files-from=po/POTFILES --output=po/peekin.pot
rm po/POTFILES
for po in po/*.po; do
    msgmerge --quiet --update --backup=none --no-fuzzy-matching --no-location --no-wrap "$po" po/peekin.pot
done
