
rule m26bb_611c17c9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.611c17c9cc000b32"
     cluster="m26bb.611c17c9cc000b32"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="allaple rahack malicious"
     md5_hashes="['73734f3cd043bd6d878fafb3e4329b335eabdd74','74245b39078575cf030b53ea2ef8d2bc0d01a5ad','b193882b1d5eb1dd80a8c4a93eef90ff8ee9f342']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.611c17c9cc000b32"

   strings:
      $hex_string = { 008801000050010000340100003a0000000000000000000000000000600000e00000000000000000000000000000000000000000000000000000000000000000 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
