
rule j26bf_18966cccc2210930
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.18966cccc2210930"
     cluster="j26bf.18966cccc2210930"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo genx heuristic"
     md5_hashes="['2c6c950cc8d98bbc99cee5a1f4fb648b71135d08','4ea4275b69ddfb6e1a3ac9f438fde7d08824aa6e','58b5ab4075961ecc65c91721b73fe852d187d004']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.18966cccc2210930"

   strings:
      $hex_string = { 756c740044656661756c740073656e646572006500646973706f73696e670076616c75650053797374656d2e5265666c656374696f6e00417373656d626c7954 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
