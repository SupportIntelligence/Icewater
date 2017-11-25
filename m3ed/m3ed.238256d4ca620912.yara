
rule m3ed_238256d4ca620912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.238256d4ca620912"
     cluster="m3ed.238256d4ca620912"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul malicious"
     md5_hashes="['1f68b6ecc7d0ca336d9c0710253a42b9','35737461b45207ce774de9a611b9eebc','df4f7db9a6a3d173f7de8d0ae6d97eee']"

   strings:
      $hex_string = { 8ea1dfb45e9d354f17d0ed0239a8d89f954aab48c7169c88d1cd9b215fb360f2d447fd831d15dc22ad24c5d81f55121a5184989087c8a7ee726d86aee37cd2a0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
