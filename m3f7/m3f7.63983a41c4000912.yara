
rule m3f7_63983a41c4000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.63983a41c4000912"
     cluster="m3f7.63983a41c4000912"
     cluster_size="12"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['260e3de26453bb092a71f7f8a0c4f008','33c4ca49d5ba19ef4a9274f8c2930140','ddd4035382a75f92f96855af178fe2df']"

   strings:
      $hex_string = { 726962652e7068703f6669643d323036353033323426616d703b733d73706f6b656e746f796f75223e0a3c696d67207372633d22687474703a2f2f7777772e66 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
