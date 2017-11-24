
rule m2319_63983ac1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.63983ac1c4000b12"
     cluster="m2319.63983ac1c4000b12"
     cluster_size="13"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['08dcd821b0e081e15a1bc4ecd24eed19','16f9429cecfb4730caaf7fb2bba51d93','e73ef47b216d700bea07d4d667f7db9b']"

   strings:
      $hex_string = { 63726962652e7068703f6669643d323036353033323426616d703b733d73706f6b656e746f796f75223e0a3c696d67207372633d22687474703a2f2f7777772e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
