
rule n26bb_599a1ec9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.599a1ec9cc000b12"
     cluster="n26bb.599a1ec9cc000b12"
     cluster_size="256"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family=""
     md5_hashes="['0e9fffcb9e9cff19a438afa67d57f84321350c53','0fb8ae1d54accbff6d76b97e1f90073ac6200cc0','8c4d360951d3499cb896f6cd84b9e7f40a30cd2c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.599a1ec9cc000b12"

   strings:
      $hex_string = { 0df8f776404d2808efec29d18dc418f50eb6e7b3bfc6b8bdb74c836be94e3e5d22bab465049092b0d91c5b7c33549ccdc63f52bb49945a72716f233dd2812e69 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
