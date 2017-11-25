
rule m3e9_5c16999ce2c3cbb1
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5c16999ce2c3cbb1"
     cluster="m3e9.5c16999ce2c3cbb1"
     cluster_size="85"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys jorik"
     md5_hashes="['18748d0eb7e2932766f67c71dced660e','1a41336ded5ce2b7fd552cfcde496ebc','83289421a6f6ed00a626b1db13a44cb5']"

   strings:
      $hex_string = { 83ec145356578965f4c745f84840400033f68975fc8b4508508b08ff51048b451066b922008975e88975e48930e8ce94fdff8a5d0c3ad8750aba6c7f4000e906 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
