
rule o26bb_19ad58f9c8800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.19ad58f9c8800b16"
     cluster="o26bb.19ad58f9c8800b16"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="decc kryptik malicious"
     md5_hashes="['25d9bc3a5960936650261aaacf83d88fed1a89ef','5dfcb4bdd47cf4314f439f118e50c005fba7c2a4','11fcda5e01aee787180545625ca65a6fa431a7da']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.19ad58f9c8800b16"

   strings:
      $hex_string = { cba98effbf9e8effad9291ffae9589ffb2a9a4feafb3b6f0898a8a9c504f4c130000000045b8466348d21eff409770f02214fcf32c27edff001cfdff2a30e260 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
