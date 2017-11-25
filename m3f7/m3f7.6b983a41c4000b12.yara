
rule m3f7_6b983a41c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.6b983a41c4000b12"
     cluster="m3f7.6b983a41c4000b12"
     cluster_size="6"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['11d633a9ece8244185d5df3e47b09f16','3cfd4585bcc0209ec8074a8dd448f3b4','fcaa306996a62a8ec9dfb2cd9670d0e4']"

   strings:
      $hex_string = { 63726962652e7068703f6669643d323036353033323426616d703b733d73706f6b656e746f796f75223e0a3c696d67207372633d22687474703a2f2f7777772e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
