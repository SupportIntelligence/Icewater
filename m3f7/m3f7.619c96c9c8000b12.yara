
rule m3f7_619c96c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.619c96c9c8000b12"
     cluster="m3f7.619c96c9c8000b12"
     cluster_size="54"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['03dda09c6aea3aebd7123f03e6ea95d6','054c35d747d1e59452d9df64bdab09cf','46972baa46424438a02fd6ab3ddd7f35']"

   strings:
      $hex_string = { 75627363726962652e7068703f6669643d323036353033323426616d703b733d7961686f6f223e0a3c696d67207372633d22687474703a2f2f7777772e666565 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
