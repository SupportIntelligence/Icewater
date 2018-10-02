
rule n2319_13966a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.13966a49c0000b12"
     cluster="n2319.13966a49c0000b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker script autolike"
     md5_hashes="['72176d4cb117263709406d3cd47db69abcc4f6df','f91c17831f30e982c55c8ce1b607a0061202eba6','f2bf9a73f15dfcbf885462a55b22fabf11f5e26e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.13966a49c0000b12"

   strings:
      $hex_string = { 2b2230313233343536373839414243444546222e63686172417428625b635d253136293b72657475726e20617d3b0a78633d2121776326262266756e6374696f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
