
rule m2321_0691534b2b1b2531
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0691534b2b1b2531"
     cluster="m2321.0691534b2b1b2531"
     cluster_size="8"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar midie scudy"
     md5_hashes="['01d32ad59134693095fab3ca80d6eb8a','50b66d249c6071181fe89eea59d6d7ea','d0cb2f75f2ab54ca6d859b7d77887311']"

   strings:
      $hex_string = { 3785aa904d662e0af1dd9b5805d4adac99316b8e5c9e0f23ab873ca53e427b8da6b4be16f603f971fd8c6080020e38119491e53db7d0d9a1bc6a786cc9a8349a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
