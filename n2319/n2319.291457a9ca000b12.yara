
rule n2319_291457a9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.291457a9ca000b12"
     cluster="n2319.291457a9ca000b12"
     cluster_size="155"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['066629e4d0c83a78020d7261b92135b6fdd3ae0e','d333953b0ec4842e3f4e2d982a7178fb83c6a932','b3e734ce8e2c3d1509231180054b4e1240b2e4ee']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.291457a9ca000b12"

   strings:
      $hex_string = { 3b66756e6374696f6e20676574546f74616c4d656d6f727928297b72657475726e20544f54414c5f4d454d4f52597d4845415033325b305d3d31363638353039 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
