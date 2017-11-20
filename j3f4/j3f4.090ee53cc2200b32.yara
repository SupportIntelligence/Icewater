
rule j3f4_090ee53cc2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f4.090ee53cc2200b32"
     cluster="j3f4.090ee53cc2200b32"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy malicious agbf"
     md5_hashes="['154a2c482c2f877d55747bb918a97099','1cb1d5145b8059857293b990da9168b2','ff71612358d4926787259007ee176ede']"

   strings:
      $hex_string = { 00008fe6f6b68de7f5fc8de4f4ff89e0f2ff88def1ff89ddf1ff86dbefff83d9eeff80d7ecff7dd5eaff7ad3e8de77d1e775000000000000000000000000c07f }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
