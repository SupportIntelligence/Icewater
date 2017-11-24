
rule m2318_797f2008d9eb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.797f2008d9eb0932"
     cluster="m2318.797f2008d9eb0932"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['2eda82255a489614ec17598cdaff4f30','7a8456de9165249da1402946902951d2','fac36122cc7f94c2442e382fc0f800e3']"

   strings:
      $hex_string = { 4f626a6563742822575363726970742e5368656c6c22290d0a5753487368656c6c2e52756e2044726f70506174682c20300d0a2f2f2d2d3e3c2f534352495054 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
