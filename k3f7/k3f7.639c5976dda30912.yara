
rule k3f7_639c5976dda30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.639c5976dda30912"
     cluster="k3f7.639c5976dda30912"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script iscp"
     md5_hashes="['0a1438fe1a1ebc53a8dd0869e1486954','1068cf11b9d3703d3026f8a02b9fcd97','b2ad7bf40d98570144c60f292b9c05be']"

   strings:
      $hex_string = { 636c6173733d22626c6f636b2d6d657461223e35206e6f76656d62726520323031362c203c6120687265663d22687474703a2f2f7777772e71756f7469646961 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
