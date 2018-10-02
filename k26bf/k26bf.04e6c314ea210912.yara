
rule k26bf_04e6c314ea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bf.04e6c314ea210912"
     cluster="k26bf.04e6c314ea210912"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="swiftbrowse browsefox yontoo"
     md5_hashes="['2204e7cd1e6fecb309e7fb1674787a6ea284488a','0133ede42e9002975e6824b16e0dd9402c74f102','d6a2cbb7d183fdab6d4b8c4487a3f27fbdde2f7a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bf.04e6c314ea210912"

   strings:
      $hex_string = { 2c280614fe012e0516252d0e2a072c21160c1b2cc02b14070891060891162de62e02162a162dd00817580c08078e6932e6172a02389effffff6f7d00000a3896 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
