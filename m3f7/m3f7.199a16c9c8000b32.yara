
rule m3f7_199a16c9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.199a16c9c8000b32"
     cluster="m3f7.199a16c9c8000b32"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['03a788a1fdb5a1798cffd156313bdcb9','0e044397b5f2e6d1e7ffaf8536282eb9','ef47f3a89ccb59f782954529516f555d']"

   strings:
      $hex_string = { 3034374456574c5726616469643d31354244535851424d574a524a5a503239474e3026267265662d72656655524c3d6874747025334125324625324670686f6e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
