
rule m2318_43b9a808dabb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.43b9a808dabb0932"
     cluster="m2318.43b9a808dabb0932"
     cluster_size="16"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['1afdc8aa6aead5dba1653329d8e35a2e','206dcf5459cbc397fdc904b334a375c0','fdf24df2b7d0a178b04242fce5b0c27c']"

   strings:
      $hex_string = { 654f626a6563742822575363726970742e5368656c6c22290d0a5753487368656c6c2e52756e2044726f70506174682c20300d0a2f2f2d2d3e3c2f5343524950 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
