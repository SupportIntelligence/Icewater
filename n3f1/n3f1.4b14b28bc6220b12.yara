
rule n3f1_4b14b28bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f1.4b14b28bc6220b12"
     cluster="n3f1.4b14b28bc6220b12"
     cluster_size="10"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos hiddenads andr"
     md5_hashes="['0f92cc500c537db113d955efc47beccb','107dc165db1768644715301b13fbc9e6','eb6d0de8bddeebf64941df576a386253']"

   strings:
      $hex_string = { 42232a7debc277921bd7301091bf08d6a547f3243d9a804f5ab9b05e727e012b02f94b45c59988d847b4706385a056ac790ed4c9f162fb6734e3643718a8f894 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
