
rule n3e7_4d22de0cc3411132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.4d22de0cc3411132"
     cluster="n3e7.4d22de0cc3411132"
     cluster_size="23"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos dldr origin"
     md5_hashes="['0e35fe3832a24813cf110b2a07df3ce1','1346469c0b979e5b60dbebf39a707149','addaeed9dd8675d9ccb37ad91b3aec02']"

   strings:
      $hex_string = { 65743d7574662d38636861727365743d69736f2d383835392d312c7574662d2c2a2c656e713d302e000ec080090a0d2023252f3a3f405b5c5d00010a00050a20 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
