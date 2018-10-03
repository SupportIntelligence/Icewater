
rule n26bb_381b6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.381b6a48c0000b12"
     cluster="n26bb.381b6a48c0000b12"
     cluster_size="463"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ransom gandcrab gandcrypt"
     md5_hashes="['469eb67fc2e079336a759b1d169c2e6858b6c694','deca2e5089f8839450b7fc3eace7bd565226caba','dfdd59621a1cc468225338f79d34ca223a1b2687']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.381b6a48c0000b12"

   strings:
      $hex_string = { c65e5dc3578bfa2bf28a043e88074784c0740583e90175f15f85c9750b880ae821ecffff6a22ebcf33f6ebd38bff558bec8b45085356578d1c85c8c241008b03 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
