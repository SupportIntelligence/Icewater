
rule m26c0_45a4ba54da06e132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26c0.45a4ba54da06e132"
     cluster="m26c0.45a4ba54da06e132"
     cluster_size="66"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="symmi virut malicious"
     md5_hashes="['83ee8e1fe3ef92c222bde17e2f75848f157ff2ba','2f21c24dc216508a628a0e5bcfb82721fe5dee41','9e5bbee1cf6cb1862c37346101f14257451f619a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26c0.45a4ba54da06e132"

   strings:
      $hex_string = { cc6a0c68c01e0201e8aefeffff33c08b4d0885c9744483f9ff743f2145fcba4d5a0000663911752b8b513c85d27c2481fa00000010731c8d040a8945e4813850 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
