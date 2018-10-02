
rule o26bb_2b19b669c8800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.2b19b669c8800b16"
     cluster="o26bb.2b19b669c8800b16"
     cluster_size="193"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mikey kryptik malicious"
     md5_hashes="['3471856e54b4bd876995e5c30240b32b16b06bbc','139e4b0adb5f88ba959a4619f9a9dc943626eaca','4b64306ada99f3378d0893b2bac4c75c99c95851']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.2b19b669c8800b16"

   strings:
      $hex_string = { cba98effbf9e8effad9291ffae9589ffb2a9a4feafb3b6f0898a8a9c504f4c130000000045b8466348d21eff409770f02214fcf32c27edff001cfdff2a30e260 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
