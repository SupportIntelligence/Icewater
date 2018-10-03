
rule m26c1_3534de39c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26c1.3534de39c8800b32"
     cluster="m26c1.3534de39c8800b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="linux gafgyt backdoor"
     md5_hashes="['c429e91024391463271221e5e9f84b828cc27ce1','82c4d0ad5d88331d438edbb407e0c55fe10d5c6d','b3da0fc4ed9c8807325247476644d5fea91092c5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26c1.3534de39c8800b32"

   strings:
      $hex_string = { 7838365f36343b20656e2d555329204170706c655765624b69742f3533352e3120284b48544d4c2c206c696b65204765636b6f29204368726f6d652f31332e30 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
