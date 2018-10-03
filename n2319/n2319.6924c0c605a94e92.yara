
rule n2319_6924c0c605a94e92
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.6924c0c605a94e92"
     cluster="n2319.6924c0c605a94e92"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['31e27473d46986ec7a6dc566dda9ac891d185ae7','effa8b7f76b3703d34579ec2a9d888c9f8b1c52a','e40bc23c60d17b6a37ff5e2d7aa7e20a27314551']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.6924c0c605a94e92"

   strings:
      $hex_string = { 73456d61696c3d66756e6374696f6e2865297b72657475726e2f5e5b5c772e2123242526e2809ac384c3b42a2b5c2f3d3f5e607b7c7d7e2d5d2b405b612d7a30 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
