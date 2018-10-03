
rule k2319_1a5e96b9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a5e96b9c8800912"
     cluster="k2319.1a5e96b9c8800912"
     cluster_size="132"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['b14a12b0042c2a701b13c20ba93fcc157bd216bb','8effb3a6229e257e51b4167392cf8c66290c9fe2','99b73de807b5103cbd6ca0da3c01b3a998930b0b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a5e96b9c8800912"

   strings:
      $hex_string = { 3139293a2830783230412c3132372e374531292929627265616b7d3b7661722076364e31763d7b2752366e273a226a222c274f3576273a66756e6374696f6e28 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
