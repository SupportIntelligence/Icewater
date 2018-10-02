
rule m26bb_631e17c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.631e17c9cc000b12"
     cluster="m26bb.631e17c9cc000b12"
     cluster_size="39"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="allaple rahack malicious"
     md5_hashes="['d6f748c9d81460a9c5c11f3c43689cde239e0108','1282d0a5cada37913bbc2d6562ee3fdb80942cb0','5ef1c7c4f33c1d31fa7e521efcad1a8f58265142']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.631e17c9cc000b12"

   strings:
      $hex_string = { 008801000050010000340100003a0000000000000000000000000000600000e00000000000000000000000000000000000000000000000000000000000000000 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
