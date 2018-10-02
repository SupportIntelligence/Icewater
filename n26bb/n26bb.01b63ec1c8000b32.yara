
rule n26bb_01b63ec1c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.01b63ec1c8000b32"
     cluster="n26bb.01b63ec1c8000b32"
     cluster_size="41"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="gandcrab ransom hpgen"
     md5_hashes="['e8bb4e4586a7f08137175c61c118a049b7f4fa09','d5bfc3bc37d343bbc5206ee0a467bc8d40104216','530cb1c75ae9ea371554d2f2ad55da3f83a4562d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.01b63ec1c8000b32"

   strings:
      $hex_string = { 4df051575056e83d7e000083c41085c07405c60300eb558b45f4483945fc0f9cc183f8fc7c2a3bc77d2684c9740a8a064684c075f98846feff75288d45f06a01 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
