
rule o26d5_599bea48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d5.599bea48c0000b32"
     cluster="o26d5.599bea48c0000b32"
     cluster_size="118"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious gifq"
     md5_hashes="['d7b59be814cc65c0f58cdd6fde68fff44c075560','e59a8cc3092b24c84d425cacdf90f9f636f83e3b','12180f007490c6777e30741f9ca0d4705fed7820']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d5.599bea48c0000b32"

   strings:
      $hex_string = { 476574436f6e736f6c65435000000000536574556e68616e646c6564457863657074696f6e46696c746572000000456e756d5265736f75726365547970657341 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
