
rule k2319_101a9699ca200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.101a9699ca200b12"
     cluster="k2319.101a9699ca200b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['84eb908b8620b3a44b0be4e9c7a1e54e2fc77d8b','1eb1f8d07ee4af33cb505b7f6ff4c5f8e0160684','1b4252a522ed7dc1fd0b2d85587ec29dafc539b0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.101a9699ca200b12"

   strings:
      $hex_string = { 66696e6564297b72657475726e20505b6c5d3b7d76617220513d2828312e34373245332c312e3436314533293e3d2832302c313031293f28307842412c307863 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
