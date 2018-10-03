
rule k2319_39151cb9caa00932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.39151cb9caa00932"
     cluster="k2319.39151cb9caa00932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['5a9fa1c0d0d5762598553b33d34e82e7594b1eba','2fca2f81d63a78bfbf17ba0a4b44d9555bfac8ce','3facd6ba85e025805514c9a6d1e2a7c28f05a547']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.39151cb9caa00932"

   strings:
      $hex_string = { 627265616b7d3b666f7228766172206d304a20696e20593657304a297b6966286d304a2e6c656e6774683d3d3d282830783146432c312e3438394533293c3078 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
