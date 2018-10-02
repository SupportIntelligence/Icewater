
rule p26bb_29976a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p26bb.29976a48c0000b12"
     cluster="p26bb.29976a48c0000b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious cheatengine hacktool"
     md5_hashes="['c1e0692c6a3d66ecd62ebac5bcc0edb8ec6570b2','522b97b2f154381f0e9e03b7cbb9c366f54af10a','9ecf528e6ee4ff607b4e247b2c651991ef897499']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=p26bb.29976a48c0000b12"

   strings:
      $hex_string = { 01eb273b7df07fd3c645f400e83653ffffa1b0264300e8ecc4ffff5885c0740f83f802740ae84d54ffff586a02ebdd8a45f45f5e5bc9c35356578d6424fc8904 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
