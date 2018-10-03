
rule n26bf_15b8149986220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bf.15b8149986220b32"
     cluster="n26bf.15b8149986220b32"
     cluster_size="42"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="passwordstealera malicious backdoor"
     md5_hashes="['a27dad09d8bf53cb38b46841954b0b3522c3b137','c5a0b32705dbb94d06d1fb37c55e51eab583a84d','dc9a379c3e2966775f6d14292412e1f9c409e52f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bf.15b8149986220b32"

   strings:
      $hex_string = { 6f5201000a590d09166a2f0b729a120070735301000a7a04020928cb0200068d4f000001510804501604508e696f5401000a262b4d080320ffff00005a6a166f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
