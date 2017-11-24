
rule m2377_63390017ded30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.63390017ded30b12"
     cluster="m2377.63390017ded30b12"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['45a84138a2e6cf82907cfa74844fef4f','539d12355f2f169251479014fa66f7ac','c81c4dcd8edf558db0d5db5036f3e405']"

   strings:
      $hex_string = { 4f626a6563742822575363726970742e5368656c6c22290d0a5753487368656c6c2e52756e2044726f70506174682c20300d0a2f2f2d2d3e3c2f534352495054 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
