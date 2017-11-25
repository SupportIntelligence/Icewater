
rule n3e7_3315cec9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.3315cec9cc000b12"
     cluster="n3e7.3315cec9cc000b12"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="downloadguide malicious classic"
     md5_hashes="['279e9d7fee5595d5ce3522caf0d17e78','29f087299381686b6e02731f661365d5','e013bc4e2dd4a726719f810fce134ea4']"

   strings:
      $hex_string = { f8037cf3eb668bc6996a1f5923d103c2c1f80581e61f00008079054e83cee0468365d80033d22bce42d3e28d4c85f08b318d3c163bfe72043bfa7307c745d801 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
