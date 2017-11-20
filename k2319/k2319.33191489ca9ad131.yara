
rule k2319_33191489ca9ad131
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.33191489ca9ad131"
     cluster="k2319.33191489ca9ad131"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cryxos redirector redir"
     md5_hashes="['60c1a3f553d9198b196ba0cec2a8f1ee','bca8f7e949039e406803fe62585ae23c','d43c5b70b47545aa9cc184d144b9aee6']"

   strings:
      $hex_string = { 53464e684d705a5a6677627862767c57474173746c41717459455a797a505571797672634e4c4f6749514c614479707673435266574b7c756e646566696e6564 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
