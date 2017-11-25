
rule m3f7_2c93008cc2210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.2c93008cc2210912"
     cluster="m3f7.2c93008cc2210912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['895baac0e9afe82754abdd2f3d9043f3','89a627a7b014f830a3896713fc38ec88','c0c00c91bbb1f195ff207d7046627e6b']"

   strings:
      $hex_string = { 46444144393644383433433035463733423743364530423431333730433141393035363841323139363937323739324538454532424631304235343746344243 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
