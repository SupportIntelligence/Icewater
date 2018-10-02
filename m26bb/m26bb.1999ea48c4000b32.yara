
rule m26bb_1999ea48c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.1999ea48c4000b32"
     cluster="m26bb.1999ea48c4000b32"
     cluster_size="4044"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hoax inbox malicious"
     md5_hashes="['84b8bb19fd0a8170c469c192efca2b7b68e861c3','fde19ecf0799f71c6adfaf3b03122f4c2678bee7','c0a7fd414666d64797baf2d8b65db4c23279e922']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.1999ea48c4000b32"

   strings:
      $hex_string = { daeb0608e4740388e0aa925089e331d2f7b60cd1400080c2308813434909c075ed09c97fe94b8a03aa39e375f8585ec390558bec83c4d45756538945fca08fe6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
