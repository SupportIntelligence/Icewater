
rule n3ed_7c16b948c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.7c16b948c8000b32"
     cluster="n3ed.7c16b948c8000b32"
     cluster_size="317"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="attribute heuristic highconfidence"
     md5_hashes="['0028856b1b6e492ce56553363323445a','00f46e5c39e92e3731c21c346ae99891','091e0d287395ab773b240ef76b9bf69a']"

   strings:
      $hex_string = { 2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a0a0000000000002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
