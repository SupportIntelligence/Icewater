
rule m3f7_51b92013044b4993
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.51b92013044b4993"
     cluster="m3f7.51b92013044b4993"
     cluster_size="434"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['003e3231dba1ea3ae8a4a883c0877d64','005888408642503fb6aab1790729eda0','0a66afc35ce2e86e9d275297e749c33a']"

   strings:
      $hex_string = { 44394241373030364644343533313338354534313942413941454236453046363238393237373241443834324443464136464330334537343333353130433543 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
