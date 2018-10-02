
rule k26bb_7ab24290dcbb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.7ab24290dcbb0912"
     cluster="k26bb.7ab24290dcbb0912"
     cluster_size="75"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="domaiq bundler nsis"
     md5_hashes="['0b6445de34f5e5b653cef970ac08a369103e499d','bacc395284f76c8d41aace2160f26d745071354a','cb905e79135014ee5e799736b5dceb4f7d4975b0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.7ab24290dcbb0912"

   strings:
      $hex_string = { f8ff152c71400085c07465837dd001755f395de87521807d0b0d742b807d0b0a74258a45f788043e463ac388450b74403b75cc7cbeeb390fb645f75057e83135 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
