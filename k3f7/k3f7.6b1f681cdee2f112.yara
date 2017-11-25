
rule k3f7_6b1f681cdee2f112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.6b1f681cdee2f112"
     cluster="k3f7.6b1f681cdee2f112"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="html iframe script"
     md5_hashes="['98de67a69daca4d5bf770b21a2c4c78d','ab6787712c05a75405377bb829450227','f6a4a61d2cb8a1fa1362bd48aaf3d23a']"

   strings:
      $hex_string = { 323743444236452d414536442d313163662d393642382d3434343535333534303030302220636f6465626173653d22687474703a2f2f646f776e6c6f61642e6d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
