
rule o26bb_39ad58f9c8800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.39ad58f9c8800b16"
     cluster="o26bb.39ad58f9c8800b16"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="decc kryptik malicious"
     md5_hashes="['ee1073141c6be6a1383f896d803f92f5e45ea714','deef0bf2ab489bd1b3c2de968a433d9acec88324','6dbe257ce5c3bc19a13f538a6b3298599ab12eb4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.39ad58f9c8800b16"

   strings:
      $hex_string = { cba98effbf9e8effad9291ffae9589ffb2a9a4feafb3b6f0898a8a9c504f4c130000000045b8466348d21eff409770f02214fcf32c27edff001cfdff2a30e260 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
