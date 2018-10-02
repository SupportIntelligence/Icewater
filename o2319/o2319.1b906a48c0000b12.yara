
rule o2319_1b906a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2319.1b906a48c0000b12"
     cluster="o2319.1b906a48c0000b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script coinminer miner"
     md5_hashes="['566c5e86d31dc04d776f9d73cf255598370f310c','5643e1fdceb8529e05017c40edebbc481a91bdd4','b923695a2166e0e3e95856a59874877312db2a8a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2319.1b906a48c0000b12"

   strings:
      $hex_string = { 626c6f636b554928746869732e6470446976293b0a09097d0a0909242e6461746128746869732e5f6469616c6f67496e7075745b305d2c2050524f505f4e414d }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
