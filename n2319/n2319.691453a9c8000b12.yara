
rule n2319_691453a9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.691453a9c8000b12"
     cluster="n2319.691453a9c8000b12"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script coinminer miner"
     md5_hashes="['03d1b2ee4fdbe16c187f5b6696cf92fbc07c4a6e','68b6b3b6ca3e3f91cfcf9157c2ba18c01b067d4b','70515721e1ede45b2a7fbdcbe6761be51ae77c17']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.691453a9c8000b12"

   strings:
      $hex_string = { 3b66756e6374696f6e20676574546f74616c4d656d6f727928297b72657475726e20544f54414c5f4d454d4f52597d4845415033325b305d3d31363638353039 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
