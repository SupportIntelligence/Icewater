
rule k2319_39993499c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.39993499c2200b32"
     cluster="k2319.39993499c2200b32"
     cluster_size="2309"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['00faeaabb50e59b401b597dbc225492b73c10202','0b15345e9d3abb1dd744b8eb893d4355c2dcbd7c','e00dfe211977e200238a36b298078c9c932853b3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.39993499c2200b32"

   strings:
      $hex_string = { 75626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c4543544544 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
