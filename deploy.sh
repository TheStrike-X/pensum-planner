#!/bin/bash
# Pensum Planner — One-shot deploy script
# Run: bash deploy.sh YOUR_CLOUDFLARE_API_TOKEN
# Token needs: D1:Edit, Workers Scripts:Edit, Pages:Edit

set -e
TOKEN=${1:-$CLOUDFLARE_API_TOKEN}
ACCOUNT_ID="ea0700117a7ad4a28a7d85bdfce9ed54"

if [ -z "$TOKEN" ]; then
  echo "Usage: bash deploy.sh <cloudflare_api_token>"
  exit 1
fi

export CLOUDFLARE_API_TOKEN=$TOKEN
export CLOUDFLARE_ACCOUNT_ID=$ACCOUNT_ID

echo "📦 Installing dependencies..."
npm install --save-dev wrangler 2>/dev/null || true

echo "🗄️  Creating D1 database..."
DB_OUTPUT=$(npx wrangler d1 create pensum-planner-db 2>&1 || true)
echo "$DB_OUTPUT"

# Extract database_id from output
DB_ID=$(echo "$DB_OUTPUT" | grep -o '"database_id": "[^"]*"' | grep -o '"[^"]*"$' | tr -d '"' || true)

if [ -z "$DB_ID" ]; then
  # DB might already exist — list and get ID
  echo "Fetching existing DB ID..."
  DB_ID=$(npx wrangler d1 list 2>&1 | grep "pensum-planner-db" | awk '{print $1}' || true)
fi

if [ -z "$DB_ID" ]; then
  echo "❌ Could not get database ID. Check your token permissions."
  exit 1
fi

echo "✅ Database ID: $DB_ID"

# Update wrangler.jsonc with real DB ID
sed -i.bak "s/PLACEHOLDER_WILL_BE_REPLACED/$DB_ID/" wrangler.jsonc && rm -f wrangler.jsonc.bak
echo "✅ wrangler.jsonc updated"

echo "🏗️  Running database schema..."
npx wrangler d1 execute pensum-planner-db --file=schema.sql --remote
echo "✅ Schema applied"

echo "🚀 Deploying to Cloudflare Pages..."
npx wrangler pages deploy . --project-name=pensum-planner --branch=main
echo "✅ Deployed!"

echo ""
echo "🎉 Done! Your app is live at https://pensum-planner.pages.dev"
echo "   Users can now create accounts and their progress syncs across devices."
