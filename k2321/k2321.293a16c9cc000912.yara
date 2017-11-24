
rule k2321_293a16c9cc000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.293a16c9cc000912"
     cluster="k2321.293a16c9cc000912"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="selfdel zbot generickd"
     md5_hashes="['2f0e9bb38da2cae16e6ce60b4720c51b','4320d5e83a69190512878a5cf42d42b1','fbea846039ef3fe8a2891963752f4f7d']"

   strings:
      $hex_string = { 64c2bdb9eaf6db35de6267cca19c3d7b43d9165e2fd9b2571df1372d6afa92f455bc31b89e70479d7e7821f9f3aee7b023f8fcb79b227712ef75a7cd5a433a7f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
