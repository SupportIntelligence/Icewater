
rule m26bb_639e9ec9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.639e9ec9cc000b12"
     cluster="m26bb.639e9ec9cc000b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="allaple rahack virut"
     md5_hashes="['f712aa219a0135a20b0e1b4b0180ead3201a381e','9a71bd70eaee0fcd4fbde9a372fbe001068029c2','34b7e97afa94f95b1021625bc1d7dda280063552']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.639e9ec9cc000b12"

   strings:
      $hex_string = { 457e0d624fce6815a969961a6c162d606fec909287e7a96b74a6421c058bb0eed0c0ab5b8159cd91d5e57a196e77b4b8031b542a5c0031235d0c9d76bf4e3021 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
