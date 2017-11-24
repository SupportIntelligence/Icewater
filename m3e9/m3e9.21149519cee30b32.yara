
rule m3e9_21149519cee30b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.21149519cee30b32"
     cluster="m3e9.21149519cee30b32"
     cluster_size="11"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="blueh mikey malicious"
     md5_hashes="['0b075f4617345d20df7056923bb4e3a3','315bae0f88eb15e114ca12f68d486c98','f773c88de313d43ad71e93b60c0d43cc']"

   strings:
      $hex_string = { 9ca152c767803a1a0d3f0f650462d786871300b6cd6c2d6edddc6451246d18e8e4b88dc01e95a2763120c4db54ada005ab0273ce2c1c145049f4faa303578261 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
