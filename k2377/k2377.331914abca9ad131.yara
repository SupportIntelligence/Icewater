
rule k2377_331914abca9ad131
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2377.331914abca9ad131"
     cluster="k2377.331914abca9ad131"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cryxos redirector redir"
     md5_hashes="['3b996f8ac0a35921fcff611db300c682','7234bcb5c4f5e921ad33c4a3dca9dbf9','d5a9a07883a1a02cee0dc140e9fa54e3']"

   strings:
      $hex_string = { 6353464e684d705a5a6677627862767c57474173746c41717459455a797a505571797672634e4c4f6749514c614479707673435266574b7c756e646566696e65 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
