
rule o26c0_4b166a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.4b166a48c0000b12"
     cluster="o26c0.4b166a48c0000b12"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious genericrxer kryptik"
     md5_hashes="['90300ec0f2b76d212b73f516daeb3e13ed530548','0f2c8a998044b492aa34480fabb5aa5df39e34a5','fd9b7af3d2f33ea39bb996c6cd7076251fb9bc0d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.4b166a48c0000b12"

   strings:
      $hex_string = { 8d46185750e88ec8ffff895e0483c40c33db89be1c02000043395de87651807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
