
rule m26bb_211496a9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.211496a9c8800b12"
     cluster="m26bb.211496a9c8800b12"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious backdoor razy"
     md5_hashes="['50fc4ce21953d7b47e067d77f6aa3e58aa910cc6','bf873eddbaf7bd06b95eedf7ae4523fd99a3b1a3','eeb00e684ca4b096e12143e69d521c14e74cedc0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.211496a9c8800b12"

   strings:
      $hex_string = { 196b67838d0a554fe8d99c95484e1261dfec203103a7abfbdeb989f0b2a821778525e5fd690c1827ef786fe3ee1be12f23f49ac17f9e92dc1691eaf9f857e0d5 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
