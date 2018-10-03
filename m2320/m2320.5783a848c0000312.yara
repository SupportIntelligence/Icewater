
rule m2320_5783a848c0000312
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2320.5783a848c0000312"
     cluster="m2320.5783a848c0000312"
     cluster_size="30"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="macro emooodldr lookslike"
     md5_hashes="['f00519c7762b6c37cf3756275449616276fdc4d2','90f8df8b49ca9c9c12af5805056ef40fc8788753','e39a04a92a60b29844dbaeae2bd6a6657ccd3a72']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2320.5783a848c0000312"

   strings:
      $hex_string = { 9a536afda432fa6b4dc9c5433e95705b3c6675244820d5d17206840802b646176dff0010e9efab98335ccc31120f8cd5f0eaaafb0d048abdc261b1d7fe2994b2 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
