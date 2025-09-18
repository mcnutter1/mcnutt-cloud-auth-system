<?php
// Simple fixed-window rate limiter using the rate_limits table

function rl_check(PDO $pdo, string $key, int $windowSec, int $limit): array {
  $st = $pdo->prepare('SELECT window_start, count FROM rate_limits WHERE key_str=?');
  $st->execute([$key]);
  $row = $st->fetch(PDO::FETCH_ASSOC);
  if(!$row){ return [true, 0]; }
  $ws = strtotime($row['window_start']);
  $now = time();
  if($ws + $windowSec <= $now){ return [true, 0]; }
  $cnt = (int)$row['count'];
  if($cnt >= $limit){
    $retry = max(1, ($ws + $windowSec) - $now);
    return [false, $retry];
  }
  return [true, 0];
}

function rl_note_failure(PDO $pdo, string $key, int $windowSec): void {
  // Upsert-like behavior: if window expired or row absent, reset; else increment
  $pdo->beginTransaction();
  try{
    $st = $pdo->prepare('SELECT window_start, count FROM rate_limits WHERE key_str=? FOR UPDATE');
    $st->execute([$key]);
    $row = $st->fetch(PDO::FETCH_ASSOC);
    $nowStr = date('Y-m-d H:i:s');
    if(!$row){
      $ins = $pdo->prepare('INSERT INTO rate_limits (key_str, window_start, count) VALUES (?,?,?)');
      $ins->execute([$key, $nowStr, 1]);
    } else {
      $ws = strtotime($row['window_start']);
      $now = time();
      if($ws + $windowSec <= $now){
        $up = $pdo->prepare('UPDATE rate_limits SET window_start=?, count=1 WHERE key_str=?');
        $up->execute([$nowStr, $key]);
      } else {
        $up = $pdo->prepare('UPDATE rate_limits SET count=count+1 WHERE key_str=?');
        $up->execute([$key]);
      }
    }
    $pdo->commit();
  }catch(Throwable $e){ if($pdo->inTransaction()) $pdo->rollBack(); }
}

