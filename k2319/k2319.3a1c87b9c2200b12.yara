
rule k2319_3a1c87b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3a1c87b9c2200b12"
     cluster="k2319.3a1c87b9c2200b12"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['4b8f2311a706e49a6ad8a152907c56233621b4da','4856ec2c26a7b21f9a1329d42b8c66e48b8cbafc','55f676417b6e1bf3cd6c9d5837d6e95752242b04']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3a1c87b9c2200b12"

   strings:
      $hex_string = { 475d213d3d756e646566696e6564297b72657475726e204d5b475d3b7d76617220563d283130392e3545313c2834312e3245312c30783845293f30783233313a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
