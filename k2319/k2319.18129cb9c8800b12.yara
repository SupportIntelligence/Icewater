
rule k2319_18129cb9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.18129cb9c8800b12"
     cluster="k2319.18129cb9c8800b12"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['6e6230ba0e22b9d29d22b6cdad5ce2d2a46b265b','8a6ff5ba2b0d2856530be8bf2cc86ade571a90f7','43a3f9b8ad5b59c7673e05d8fb9b3219347a37ed']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.18129cb9c8800b12"

   strings:
      $hex_string = { 39293a28307845462c3131322e292929627265616b7d3b7661722056324e353d7b27563354273a226c65666768222c274639273a66756e6374696f6e28712c41 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
