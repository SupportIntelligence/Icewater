
rule n3e9_1697154bc6220b54
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1697154bc6220b54"
     cluster="n3e9.1697154bc6220b54"
     cluster_size="1735"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple virut rahack"
     md5_hashes="['0008391a359920e36d93638c0e75a4a4','00165ed8776bf6f804043bcdcf0fbe1d','02c55ec0eec70762802ecc0e67a25b1f']"

   strings:
      $hex_string = { 34e5950b301607adfaf6431ad608e827cb9385b132243fd8db3d5d442c5ea196cf399d2605c366d3de1278f72555da8edd0fc403e43cbe4574f577b3981f628a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
