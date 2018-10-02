
rule n26d7_2d9d96b9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d7.2d9d96b9c8800b32"
     cluster="n26d7.2d9d96b9c8800b32"
     cluster_size="314"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="xcnfe malicious gifq"
     md5_hashes="['b0389540e5022b6c8dcc001a59e4c6bda6bfffde','f17c2c86edc9bfebd9dc41aef57c5e6516e32007','4a1a49a3d27409016e2239c5278fd1e6c4993222']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d7.2d9d96b9c8800b32"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
