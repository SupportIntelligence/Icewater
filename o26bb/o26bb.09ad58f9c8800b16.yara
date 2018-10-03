
rule o26bb_09ad58f9c8800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.09ad58f9c8800b16"
     cluster="o26bb.09ad58f9c8800b16"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="decc kryptik malicious"
     md5_hashes="['9eec7f062f43ce8b8bd169d60445bea553f4cd06','6df7e0b4fb5ad5ec5bdb92a9b5d4042e0badb3fc','41b6373a93fec2cfdda5c2fcee1ac85b0ec7a51e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.09ad58f9c8800b16"

   strings:
      $hex_string = { cba98effbf9e8effad9291ffae9589ffb2a9a4feafb3b6f0898a8a9c504f4c130000000045b8466348d21eff409770f02214fcf32c27edff001cfdff2a30e260 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
