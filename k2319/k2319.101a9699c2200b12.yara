
rule k2319_101a9699c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.101a9699c2200b12"
     cluster="k2319.101a9699c2200b12"
     cluster_size="42"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['74d73b4511d964cd7ed7c2b90cdff1c05ba87253','dc14a1993d06a4ce7442c7da13e251df0f807a5a','d0d78c057efad87cab49e660899d515d995ce6cb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.101a9699c2200b12"

   strings:
      $hex_string = { 7b72657475726e20505b6c5d3b7d76617220513d2828312e34373245332c312e3436314533293e3d2832302c313031293f28307842412c307863633965326435 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
