#!/usr/bin/env bash
# 6주차 - OSPF 재수렴 관찰
#
#   bash w06-routing/scenario.sh up        토폴로지 올리기
#   bash w06-routing/scenario.sh routes    라우팅 표 보기
#   bash w06-routing/scenario.sh cut       링크 끊고 재수렴 시간 재기
#   bash w06-routing/scenario.sh restore   링크 복구
#   bash w06-routing/scenario.sh cost      링크 비용 바꾸기
#   bash w06-routing/scenario.sh down      정리
set -u
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
cd "$(dirname "$0")/.." || exit 1
OUT="w06-routing/out"; mkdir -p "$OUT"
DC="docker compose --profile routing"

case "${1:-}" in
  up)
    $DC up -d
    echo "라우터 3대를 올렸습니다. OSPF 인접 수립까지 30초쯤 기다리세요."
    sleep 30
    $DC exec -T r1 vtysh -c "show ip ospf neighbor"
    ;;

  routes)
    for r in r1 r2 r3; do
      echo "===== $r ====="
      $DC exec -T $r vtysh -c "show ip route ospf"
    done
    ;;

  cut)
    echo "== 끊기 전 =="
    $DC exec -T r1 vtysh -c "show ip route ospf" | tee "$OUT/route-before.txt"

    echo
    echo "r1 의 eth1 (net_b, r1-r2 링크) 을 내립니다."
    START=$(date +%s)
    $DC exec -T r1 ip link set eth1 down

    # 경로가 바뀔 때까지 1초 간격으로 확인
    for i in $(seq 1 60); do
      sleep 1
      NOW=$($DC exec -T r1 vtysh -c "show ip route ospf" 2>/dev/null)
      if [ "$NOW" != "$(cat "$OUT/route-before.txt")" ]; then
        END=$(date +%s)
        echo "재수렴 감지: $((END - START)) 초" | tee "$OUT/reconverge.txt"
        echo "$NOW" | tee "$OUT/route-after.txt"
        exit 0
      fi
    done
    echo "60초 안에 경로가 바뀌지 않았습니다. dead interval 을 확인하세요." \
      | tee "$OUT/reconverge.txt"
    ;;

  restore)
    $DC exec -T r1 ip link set eth1 up
    echo "복구했습니다. 30초 뒤 routes 로 확인하세요."
    ;;

  cost)
    echo "r1 의 eth0 (net_a) 비용을 10 에서 100 으로 올립니다."
    $DC exec -T r1 vtysh -c "configure terminal" \
                    -c "interface eth0" -c "ip ospf cost 100"
    sleep 15
    $DC exec -T r1 vtysh -c "show ip route ospf"
    echo
    echo "경로가 바뀌었는지 보세요. OSPF 는 홉 수가 아니라 비용으로 고릅니다."
    ;;

  down)
    $DC down
    ;;

  *)
    sed -n '2,10p' "$SELF"
    ;;
esac
