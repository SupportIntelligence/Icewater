
rule m3f7_63983ec1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.63983ec1c4000b12"
     cluster="m3f7.63983ec1c4000b12"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['5c03d0e7d6a8694a90e034a2ce559d60','5e3955f3d292dba21d6ed1385ae0b132','c8553b9427b056881dc4b077d49c947e']"

   strings:
      $hex_string = { 75627363726962652e7068703f6669643d323036353033323426616d703b733d676f6f676c65223e0a3c696d67207372633d22687474703a2f2f7777772e6665 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
