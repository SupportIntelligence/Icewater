
rule m2321_3b954e5fc2220b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.3b954e5fc2220b16"
     cluster="m2321.3b954e5fc2220b16"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma tinba"
     md5_hashes="['1db8cbc1499a0cc849ffdf8d95816d39','35179425bce28006e1e96d2ea735f9bb','b0115a3cb0ec0d2d6b8808f85b9655c1']"

   strings:
      $hex_string = { bb019d812e41c76016432761e2bc72c3eae763d0791842be0997af8680391d1f9a902809766a305836c25f36f49cac2c5c6c6cb0bf1326919564a5e62a8bc6eb }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
