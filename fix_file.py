import sys
content = open('packages/core-ts/src/auth/local-oauth-app.ts').read()
# Replace backslash-backtick with backtick
content = content.replace('\\`', '`')
# Replace backslash-dollar with dollar
content = content.replace('\\$', '$')
# Wait, if they are already gone as per cat -A, I need to add them back if they were meant to be template literals.
# In "return ${protocol}://${host}", it should be "`return `${protocol}://${host}`"
# Let's check my previous cat output.
# It showed: "return \`${protocol}://${host}\`"
# No, it showed "return \`\${protocol}://\${host}\`" in the heredoc.
# If I ran sed -i 's/\\`//g', it removed the backslash but kept the character.
# So "return `\${protocol}://\${host}`" became "return `${protocol}://${host}`" but WITHOUT backticks?
# No, cat -A showed "return ${protocol}://${host}" (no backticks).
open('packages/core-ts/src/auth/local-oauth-app.ts', 'w').write(content)
