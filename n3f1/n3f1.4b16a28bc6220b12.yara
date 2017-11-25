
rule n3f1_4b16a28bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f1.4b16a28bc6220b12"
     cluster="n3f1.4b16a28bc6220b12"
     cluster_size="37"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="obfus androidos andr"
     md5_hashes="['00386a6a48d5692ac21ebd0101aea7f8','016b05f0c5a701069f1c0347cf1ec3e5','7e85a3ec4ca30a1eb76b75e25cfc542f']"

   strings:
      $hex_string = { 42232a7debc277921bd7301091bf08d6a547f3243d9a804f5ab9b05e727e012b02f94b45c59988d847b4706385a056ac790ed4c9f162fb6734e3643718a8f894 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
