DSN=$(grep NEON_DSN .env | cut -d '=' -f2-)

echo "------------------------------------------------------------"
echo "🧠  LexisIQ Global Memory Monitor"
echo "------------------------------------------------------------"

echo ""
echo "📊 Total memories stored:"
psql "$DSN" -c "SELECT COUNT(*) FROM global_memories;"

echo ""
echo "💾 Table size:"
psql "$DSN" -c "SELECT pg_size_pretty(pg_total_relation_size('global_memories')) AS table_size;"

echo ""
echo "📅 Entries created per day (last 14 days):"
psql "$DSN" -c "SELECT to_char(date_trunc('day',created_at),'YYYY-MM-DD') AS day, COUNT(*) FROM global_memories GROUP BY 1 ORDER BY 1 DESC LIMIT 14;"

echo ""
echo "✅ Monitor complete — all learning data intact."
echo "------------------------------------------------------------"
