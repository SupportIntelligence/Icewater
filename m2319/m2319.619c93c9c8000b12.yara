
rule m2319_619c93c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.619c93c9c8000b12"
     cluster="m2319.619c93c9c8000b12"
     cluster_size="6"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['029bb294076486932ec5efa9c6624818','1077b560cb06ab2c8ddd3e1c22b9d693','8ef74c214e2967aa27a2c94e521f3671']"

   strings:
      $hex_string = { 75627363726962652e7068703f6669643d323036353033323426616d703b733d626c6f676c696e6573223e0a3c696d67207372633d22687474703a2f2f777777 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
