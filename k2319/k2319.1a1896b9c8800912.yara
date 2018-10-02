
rule k2319_1a1896b9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a1896b9c8800912"
     cluster="k2319.1a1896b9c8800912"
     cluster_size="56"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['640efb5ac576ee1a6a272c7e153f89bb6d40f96f','159462bb8e64d0048996e3cb49b283c5a7d3211a','9851b25b772ff1f26d6eeb780ad3fd36d688efb1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a1896b9c8800912"

   strings:
      $hex_string = { 3a283131342e2c30784132292929627265616b7d3b766172206f3943333d7b27733142273a66756e6374696f6e28442c46297b72657475726e20443c463b7d2c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
