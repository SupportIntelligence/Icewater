
rule k2319_4992a50bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.4992a50bc6220b12"
     cluster="k2319.4992a50bc6220b12"
     cluster_size="193"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector fakejquery script"
     md5_hashes="['31d757ebcdb7da67acbeebf89dc243a8c85c3710','379bbf321bbcfa9752796825c367a3bbab446138','6246bae8ea5e957c10f393132b7cc4602cf12ae6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.4992a50bc6220b12"

   strings:
      $hex_string = { 735c2f77702d656d6f6a692d72656c656173652e6d696e2e6a733f7665723d342e342e3130227d7d3b0a0909092166756e6374696f6e28612c622c63297b6675 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
