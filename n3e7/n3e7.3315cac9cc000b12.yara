
rule n3e7_3315cac9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.3315cac9cc000b12"
     cluster="n3e7.3315cac9cc000b12"
     cluster_size="15"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="downloadguide bundler downloaderguide"
     md5_hashes="['38e2bcf886441debd3ec4806ed5c377c','3a548b46f799e417c412342318486e23','f7030cb250b5ae899a69a67e6b784b9a']"

   strings:
      $hex_string = { f8037cf3eb668bc6996a1f5923d103c2c1f80581e61f00008079054e83cee0468365d80033d22bce42d3e28d4c85f08b318d3c163bfe72043bfa7307c745d801 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
