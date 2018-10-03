
rule n2319_39193949c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.39193949c8000b32"
     cluster="n2319.39193949c8000b32"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker likejack script"
     md5_hashes="['b70d3224940c5def41f6a5051f6fcf952d3177db','bd0bc4068861822707e70015a478a3e76dc3f16a','6d9dce66cb14a410280c506cb0ae5831586dbbd3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.39193949c8000b32"

   strings:
      $hex_string = { 64656f22292e73706c697428272c27293b20666f7220287661722069203d20303b2069203c2068746d6c352e6c656e6774683b20692b2b29207b20646f63756d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
