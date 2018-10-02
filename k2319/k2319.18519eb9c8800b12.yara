
rule k2319_18519eb9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.18519eb9c8800b12"
     cluster="k2319.18519eb9c8800b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik diplugem czyf"
     md5_hashes="['801768cc2873e090b1ef49dfeb7d423dadbc87af','0504d711bb2fdbffd4bd42c5194083781d7a27e3','6ac6c431d034cb8e694649a5d05f305ca5370e70']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.18519eb9c8800b12"

   strings:
      $hex_string = { 415b4b5d213d3d756e646566696e6564297b72657475726e20415b4b5d3b7d766172204c3d283078343c283132332c3630293f28352e393545322c3078636339 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
