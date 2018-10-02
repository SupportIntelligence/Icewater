
rule m2320_56a1ac49c0000112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2320.56a1ac49c0000112"
     cluster="m2320.56a1ac49c0000112"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="macro lookslike malicious"
     md5_hashes="['43676f119485cb6109e0f660840dff2c81fc7195','a0346b3444cab1890196ecc08ac1e039e54084f8','835ec9df6fdb2cc4d19292f86bb526cf8f006412']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2320.56a1ac49c0000112"

   strings:
      $hex_string = { 9a536afda432fa6b4dc9c5433e95705b3c6675244820d5d17206840802b646176dff0010e9efab98335ccc31120f8cd5f0eaaafb0d048abdc261b1d7fe2994b2 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
