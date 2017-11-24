
rule m2319_639916c9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.639916c9c4000b12"
     cluster="m2319.639916c9c4000b12"
     cluster_size="9"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker script"
     md5_hashes="['07110337a5dc12abfa87c5d5549cfde2','3515b403ae716dcbc176d143387e1154','fda0b930e2d65ab20c85738eab6d8310']"

   strings:
      $hex_string = { 726962652e7068703f6669643d323036353033323426616d703b733d73706f6b656e746f796f75223e0a3c696d67207372633d22687474703a2f2f7777772e66 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
