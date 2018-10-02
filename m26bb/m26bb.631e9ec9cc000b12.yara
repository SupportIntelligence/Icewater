
rule m26bb_631e9ec9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.631e9ec9cc000b12"
     cluster="m26bb.631e9ec9cc000b12"
     cluster_size="21"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="allaple rahack malicious"
     md5_hashes="['f7792009f52a0d721a061525bfa0c7477772cc35','a4eb137127121c151ee8a5d6d560f1afc5ac2164','6393b12c63bb2d2c0d5b6e26b2c8bbd6bbafbd8c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.631e9ec9cc000b12"

   strings:
      $hex_string = { 457e0d624fce6815a969961a6c162d606fec909287e7a96b74a6421c058bb0eed0c0ab5b8159cd91d5e57a196e77b4b8031b542a5c0031235d0c9d76bf4e3021 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
