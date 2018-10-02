
rule m26bb_1bb994829a9b4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.1bb994829a9b4912"
     cluster="m26bb.1bb994829a9b4912"
     cluster_size="170"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ransom gandcrab dangerousobject"
     md5_hashes="['25ed7698a95ec8571b892ab6e4f4a096f456b7aa','8bf3a9957ba44a905982bf2da5a6940aa53c7364','c92e674e5b85a1c9d95c0ff10499a831cf418f03']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.1bb994829a9b4912"

   strings:
      $hex_string = { 8d46185750e87bcaffff895e0483c40c33db89be1c02000043395de87651807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
