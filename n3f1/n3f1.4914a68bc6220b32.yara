
rule n3f1_4914a68bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f1.4914a68bc6220b32"
     cluster="n3f1.4914a68bc6220b32"
     cluster_size="25"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hiddenads androidos afea"
     md5_hashes="['0699734d84d91d7fe8eabe034642a1d0','0eea1751f7e3583e71d38dfe6c5f2294','92ffa315d883d4779ad2dfb7a93542f0']"

   strings:
      $hex_string = { 42232a7debc277921bd7301091bf08d6a547f3243d9a804f5ab9b05e727e012b02f94b45c59988d847b4706385a056ac790ed4c9f162fb6734e3643718a8f894 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
