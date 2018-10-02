
rule m26bb_1a5ce44944000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.1a5ce44944000b32"
     cluster="m26bb.1a5ce44944000b32"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virtob virut malicious"
     md5_hashes="['61b2f3ed1a80468ccb1a66ffb1b3eab9f00e7856','986512fef28f3c69e0a4bf834c742ac052815359','3dc804c88aafa569549a1ef3dcfb042ff8d4f8d0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.1a5ce44944000b32"

   strings:
      $hex_string = { 764de77788c7e7779050e7777d15f5776331e7775606e877a707e7778198e7771806e877000000006c57c471ba14c27100000000dd32bf76b51dbf76221cbf76 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
