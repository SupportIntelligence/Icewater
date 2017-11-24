
rule j3f9_4246b32996930914
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f9.4246b32996930914"
     cluster="j3f9.4246b32996930914"
     cluster_size="4"
     filetype = "MS-DOS executable"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy malicious malob"
     md5_hashes="['375ff16892929c159cd3b2f3b1dfb449','4d74b960e5e09a6cbc4895f32e64c02a','e4709d5b925b0cc0cd05f60c33a1a8f9']"

   strings:
      $hex_string = { a804f31fbd58051bdf8550495302d036745c04bf3715b98bd204af9a14ffd22e2106fb1ae4620cffd2aeb0b8b8688020b5388200bd01e00b7a89da701908105f }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
