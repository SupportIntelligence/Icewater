
rule m26c0_45a4ba54da126132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26c0.45a4ba54da126132"
     cluster="m26c0.45a4ba54da126132"
     cluster_size="53"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virut virtob malicious"
     md5_hashes="['2f4eea055087cda9909bba7d1ffe26317a7ebf63','ea6b3d00446df84ba28519aa79b85a7ba2f9e586','78945af5e9a9269f9f01c3ebfb4f88c458068f31']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26c0.45a4ba54da126132"

   strings:
      $hex_string = { cc6a0c68c01e0201e8aefeffff33c08b4d0885c9744483f9ff743f2145fcba4d5a0000663911752b8b513c85d27c2481fa00000010731c8d040a8945e4813850 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
