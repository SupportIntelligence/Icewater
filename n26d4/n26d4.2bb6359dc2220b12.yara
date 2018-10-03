
rule n26d4_2bb6359dc2220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d4.2bb6359dc2220b12"
     cluster="n26d4.2bb6359dc2220b12"
     cluster_size="20"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kelios neoreklami malicious"
     md5_hashes="['c43ab74f8dc6871af39956633d77f4c286547eac','2e528c8e1ece8b8c51ed685e4605990d7e9332d4','eec50ebdf9afb97eb9f31754b9e439c5c63d2605']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d4.2bb6359dc2220b12"

   strings:
      $hex_string = { 40eb028bc2b9c30972da3bc81bc0f7d88945d88855df807ddf00740a5252ff1570f0051033d28b43048946308955e4c745e01f9466518955d4c745e83281cfb3 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
