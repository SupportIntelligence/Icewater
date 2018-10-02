
rule k2319_6952c38bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.6952c38bc6220b32"
     cluster="k2319.6952c38bc6220b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug kryptik diplugem"
     md5_hashes="['3573e8fc254fc5d3dfb0552ce412e363d75e947f','35f3da3068feaa1532541c6e5df0d74af33cd8c4','3a3fa24d50e7f6d7d0bf57cee32b546e2341fc05']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.6952c38bc6220b32"

   strings:
      $hex_string = { 2834312e3545312c3078313738292929627265616b7d3b7661722062387937473d7b2771395a273a2272222c276f3747273a66756e6374696f6e284a2c48297b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
