#!/bin/bash
# Quick diagnostic script for debugging stuck fuzzing

set -e

echo "====== SC-SENTINEL 诊断脚本 ======"
echo ""

# 1. 检查容器状态
echo "1. 检查容器状态..."
docker compose ps

# 2. 检查是否有卡住的沙箱容器
echo ""
echo "2. 检查沙箱容器..."
SANDBOX_CONTAINERS=$(docker ps -a --filter "name=sentinel_harness" --filter "name=sentinel_fuzzer" --format "{{.Names}}" | wc -l)
if [ "$SANDBOX_CONTAINERS" -gt 0 ]; then
    echo "⚠️  发现 $SANDBOX_CONTAINERS 个沙箱容器:"
    docker ps -a --filter "name=sentinel_harness" --filter "name=sentinel_fuzzer"

    read -p "是否清理这些容器? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker ps -a --filter "name=sentinel_harness" --filter "name=sentinel_fuzzer" -q | xargs -r docker rm -f
        echo "✓ 已清理"
    fi
else
    echo "✓ 没有残留的沙箱容器"
fi

# 3. 检查worker日志最后错误
echo ""
echo "3. Worker 最近错误:"
docker logs sentinel_worker 2>&1 | grep -i "error\|failed\|exception" | tail -5

# 4. 检查最近任务状态
echo ""
echo "4. 最近任务状态:"
docker exec sentinel_postgres psql -U sentinel_admin -d sentinel_db -c \
  "SELECT id, project_name, status, error_message FROM task ORDER BY created_at DESC LIMIT 3;"

# 5. 检查harness bundle
echo ""
echo "5. Harness bundles:"
docker exec sentinel_worker bash -c "ls -lt /app/uploads/harness_bundles/ | head -5"

# 6. 重启worker
echo ""
read -p "是否重启worker以应用代码修复? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "重启 worker..."
    docker compose restart worker
    echo "✓ Worker已重启"
fi

echo ""
echo "====== 诊断完成 ======"
echo ""
echo "建议操作:"
echo "1. 重新上传测试项目"
echo "2. 监控日志: docker logs -f sentinel_worker"
echo "3. 如果仍然卡住，检查沙箱镜像: docker images | grep sentinel-sandbox"
