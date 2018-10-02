
rule k2319_292d1ab9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.292d1ab9c8800b32"
     cluster="k2319.292d1ab9c8800b32"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['0d1407ab5ec8913da7aca9d760a1c51e91ef090f','38e83c07a3684decbaf91bbc84278871678da47f','0ee535203be69f78c4e496f00ff373820c6307d4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.292d1ab9c8800b32"

   strings:
      $hex_string = { 2e354531293f2830783235332c313139293a28307843362c35332e292929627265616b7d3b76617220563749363d7b274836273a66756e6374696f6e286e2c64 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
