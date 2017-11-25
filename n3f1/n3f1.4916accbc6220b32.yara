
rule n3f1_4916accbc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f1.4916accbc6220b32"
     cluster="n3f1.4916accbc6220b32"
     cluster_size="73"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hiddenads andr androidos"
     md5_hashes="['0113efbc3c4ed9bd5629f6b30f4cb8f7','056a8bf94ef51654c53ca1200fa139eb','3a2399f1bf0e13a41927274b9bec649a']"

   strings:
      $hex_string = { 42232a7debc277921bd7301091bf08d6a547f3243d9a804f5ab9b05e727e012b02f94b45c59988d847b4706385a056ac790ed4c9f162fb6734e3643718a8f894 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
