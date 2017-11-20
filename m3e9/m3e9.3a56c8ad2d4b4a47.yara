
rule m3e9_3a56c8ad2d4b4a47
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a56c8ad2d4b4a47"
     cluster="m3e9.3a56c8ad2d4b4a47"
     cluster_size="8"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['aabec8a67ae4dbea44b4c56487442512','bfba2ec3ad1bdeac54e7ba1993023550','de6767d6b26465e7951060a920ed46ff']"

   strings:
      $hex_string = { cbd5da828fce7c14d96dff37c3b642dd4c0062e66ca1a7de571ad7594aaba218307eb435554f9883515da65c2de0126094f779958cbf191ecfea3f1f6447333d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
