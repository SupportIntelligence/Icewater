
rule m2319_639c93c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.639c93c9c8000b12"
     cluster="m2319.639c93c9c8000b12"
     cluster_size="18"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['07cd0f08181de6769514dd97f49479b2','1a7c4f6e8421879eb26c54ebe88348c9','cd59d5f09df2951827deaab44f4b7ab1']"

   strings:
      $hex_string = { 63726962652e7068703f6669643d323036353033323426616d703b733d73706f6b656e746f796f75223e0a3c696d67207372633d22687474703a2f2f7777772e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
