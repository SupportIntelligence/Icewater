
rule k2319_185996b9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.185996b9c8800912"
     cluster="k2319.185996b9c8800912"
     cluster_size="49"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['211467b7b88c4ceadc24f12542e4242d18943739','50885c53a282fd2f673353affc6387b91e08a053','a50abdc63e03dc90815e1a26316bd2b20bd13782']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.185996b9c8800912"

   strings:
      $hex_string = { 3a28307833462c38362e354531292929627265616b7d3b7661722048324330383d7b2742324f273a362c274b3038273a66756e6374696f6e28742c57297b7265 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
