
rule m3e9_0f9a96adc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0f9a96adc6220b12"
     cluster="m3e9.0f9a96adc6220b12"
     cluster_size="33"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="genkryptik ansy bypassuac"
     md5_hashes="['012084234925bcf014a76400d00abcb0','01f2f655f11565f4d7be564bd9df1667','b3c221060c6911d4601cc1633870e0e9']"

   strings:
      $hex_string = { 06752fd1c6dd5f855704fed3fbf6ffa63e9fed372d86d072406fc76eadbdec772bbcebba167d91fdd8b67a93955a0df1e5426b7f00ab2e418f9436ee4a9ee1f2 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
