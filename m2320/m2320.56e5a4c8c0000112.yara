
rule m2320_56e5a4c8c0000112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2320.56e5a4c8c0000112"
     cluster="m2320.56e5a4c8c0000112"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="macro lookslike malicious"
     md5_hashes="['04998cf769ba7cfc0e28c18a38a3022bc9eba72e','870780902c6d47c33f2ba084aa5d63cdbaa4c5cb','f104aa3738f4643e6301643a290a5b05c8e50a6b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2320.56e5a4c8c0000112"

   strings:
      $hex_string = { 9a536afda432fa6b4dc9c5433e95705b3c6675244820d5d17206840802b646176dff0010e9efab98335ccc31120f8cd5f0eaaafb0d048abdc261b1d7fe2994b2 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
