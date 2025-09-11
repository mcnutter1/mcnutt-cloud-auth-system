<?php
class AppModel {
  public function __construct(private PDO $pdo){}
  public function findByAppId(string $appId){
    $st=$this->pdo->prepare('SELECT * FROM apps WHERE app_id=? LIMIT 1');
    $st->execute([$appId]); return $st->fetch(PDO::FETCH_ASSOC);
  }
  public function getSecretForVerify(array $app): string {
    $envKey = 'APP_SECRET_'.strtoupper(str_replace(['-',' '],'_',$app['app_id']));
    $secret = getenv($envKey) ?: null;
    if(!$secret) { die('App secret not configured'); }
    return $secret;
  }
}
