
rule o3e9_32b94be2d9bb1916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.32b94be2d9bb1916"
     cluster="o3e9.32b94be2d9bb1916"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmu mikey fakeav"
     md5_hashes="['b2b054d853121534fea76e842e7703aa','c0e1b51adce25c2707e8411b9f2cc715','e486c0ef4faed2e7fb0b5163929f7720']"

   strings:
      $hex_string = { b8f5480b6242644c4ea0dddccd65a98c197c9cd193f9c16b080f966d097da4e9c8c5864d6e3a604f5c54e561ee2e7fcbb73de8816992c9300d034a41ea633252 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
