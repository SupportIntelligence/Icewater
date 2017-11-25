
rule j3f4_090f6c38c1800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f4.090f6c38c1800b32"
     cluster="j3f4.090f6c38c1800b32"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy malicious agbf"
     md5_hashes="['0de76a2c7d6dc40ef1e40831ad3689eb','c4cb542400b9e75fc87e54039fdc4e82','fa9d69a7d8c6907f4f46fca12a556bec']"

   strings:
      $hex_string = { 00008fe6f6b68de7f5fc8de4f4ff89e0f2ff88def1ff89ddf1ff86dbefff83d9eeff80d7ecff7dd5eaff7ad3e8de77d1e775000000000000000000000000c07f }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
