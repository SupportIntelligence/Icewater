
rule m3e9_3a79600ac0000b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a79600ac0000b14"
     cluster="m3e9.3a79600ac0000b14"
     cluster_size="62"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre wapomi"
     md5_hashes="['025dee2c733109130eb3da29faa20d8e','042bff2a65f4a9204f791976017b0ea8','6e44dd7345f8994a27ea17bc5567be6d']"

   strings:
      $hex_string = { 5c6acc4dba332b1bc4420a5732451496bdc29d408f3ef2efeda7b4fbb26f5e2f65d78e45be53031af5e4269b1275e8847677594fb119165dee47e60ac58c6989 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
