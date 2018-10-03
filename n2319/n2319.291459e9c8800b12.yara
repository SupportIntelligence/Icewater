
rule n2319_291459e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.291459e9c8800b12"
     cluster="n2319.291459e9c8800b12"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['3653bf3756911514a69c33d0bc8fa94dbe7a18e9','e5998677a8577add1ff692f9e9aa978ea2c7ddcf','bd15c46f23bcd6721d220d88e62a21487fd005bc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.291459e9c8800b12"

   strings:
      $hex_string = { 3b66756e6374696f6e20676574546f74616c4d656d6f727928297b72657475726e20544f54414c5f4d454d4f52597d4845415033325b305d3d31363638353039 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
