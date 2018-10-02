
rule m26bb_611e17c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.611e17c9cc000b12"
     cluster="m26bb.611e17c9cc000b12"
     cluster_size="58"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="allaple rahack malicious"
     md5_hashes="['bc2b082cb3a9e362944d8d99b6910c9e79107954','80ae55ca56a1c5a18c7e37b1b351e4b16e6e0ba0','fe9c17b446d9865f8df6a18cd2a98c9a37ac1380']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.611e17c9cc000b12"

   strings:
      $hex_string = { 008801000050010000340100003a0000000000000000000000000000600000e00000000000000000000000000000000000000000000000000000000000000000 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
