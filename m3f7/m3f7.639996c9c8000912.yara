
rule m3f7_639996c9c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.639996c9c8000912"
     cluster="m3f7.639996c9c8000912"
     cluster_size="13"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['05b8f2ba06e535a0d90c85ae40c0495b','2b410aa032bc507130c9a1b158bd4431','feaab19c34c746d33a553c3edf7966ce']"

   strings:
      $hex_string = { 75627363726962652e7068703f6669643d323036353033323426616d703b733d676f6f676c65223e0a3c696d67207372633d22687474703a2f2f7777772e6665 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
