
rule m26d7_239d1a99c2200b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26d7.239d1a99c2200b16"
     cluster="m26d7.239d1a99c2200b16"
     cluster_size="24"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="remoteadmin winvnc based"
     md5_hashes="['585aaea49a0d72aeaed1cd554b08934933b45def','74f9073dcdca8a0d1112f60ddf6076fe9d632312','4df6cd18ea1a5da9a5e32ae8ac119efd8c09ca73']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26d7.239d1a99c2200b16"

   strings:
      $hex_string = { 742408578a460f3a420f75210fb6c833ff85c976118bc22bf28a14063a10750d47403bf972f3b0015f5ec2080032c0ebf7b8132d4100e815aa00005153568bf1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
