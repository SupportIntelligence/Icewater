
rule k2321_29259162dbeb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.29259162dbeb1912"
     cluster="k2321.29259162dbeb1912"
     cluster_size="13"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi vbkrypt"
     md5_hashes="['05132ebefbb08d678a2d1cc6759afba4','0995f66bf97cebfefd5c6fbd3b0554c5','fad993ef9264251977c3582792703c55']"

   strings:
      $hex_string = { dc404a979f8ca1805f4408f845c75dd6c671265235eeb4e51a6ccb9bb12d7f1879d57723a3e4b84b6027398a2505dcd35a0b74aac15e6d03bebb19c55e55fcec }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
