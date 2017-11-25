
rule n3f1_6914a4cbc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f1.6914a4cbc6220b32"
     cluster="n3f1.6914a4cbc6220b32"
     cluster_size="38"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="andr androidos axent"
     md5_hashes="['0b2ab7c82453ec7909a6288a5ff3cfd8','0c66eaee5b6f5884f9c596da3b0faf30','5e1e803828e1f95330303a64e066cbb8']"

   strings:
      $hex_string = { 42232a7debc277921bd7301091bf08d6a547f3243d9a804f5ab9b05e727e012b02f94b45c59988d847b4706385a056ac790ed4c9f162fb6734e3643718a8f894 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
