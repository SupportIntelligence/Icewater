
rule j3f7_4a249a912dad4a9a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f7.4a249a912dad4a9a"
     cluster="j3f7.4a249a912dad4a9a"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cryxos html expkit"
     md5_hashes="['67522a1663b8503b0044739fac7e2f1f','994066d568d2c1ba0a2e3a2f68fdbdd7','f588a87adbe574be5f05cd822c3a5ddb']"

   strings:
      $hex_string = { 6578742f6a617661736372697074223e0d0a3c212d2d0d0a646f63756d656e742e777269746528756e6573636170652827253363253634253639253736253230 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
