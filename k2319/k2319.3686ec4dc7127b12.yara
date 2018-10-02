
rule k2319_3686ec4dc7127b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3686ec4dc7127b12"
     cluster="k2319.3686ec4dc7127b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script fffazo"
     md5_hashes="['13d1ee5d08c92bd081c23306eea2beae63acb9cb','5e785532aeeb9d9792645ce488f3d9c9b650418b','ec1ab0dd997d5f0b6f521e247db8d8966ac435e5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3686ec4dc7127b12"

   strings:
      $hex_string = { 3f28352e383245322c313139293a2833352c3132352e292929627265616b7d3b7661722051305137593d7b27703547273a2230222c27763347273a2266696775 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
