
rule m3e9_13b96b34c932e912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13b96b34c932e912"
     cluster="m3e9.13b96b34c932e912"
     cluster_size="49"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shipup lethic kryptik"
     md5_hashes="['03402df63cbdeda6e6998154a716ce4f','046c5bcc8f96b66ff2d2752683db608f','62e8ddd1fd89bab5c4e1d633ccb6887c']"

   strings:
      $hex_string = { 132262bc8d63a4b4905e9fac956baca4d6a7e59c34badb941dbbdc8c29b7d88420aecf7c48c6c77435c3c46ce855b764e552b45ce36caa54e966a84c31bfc044 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
