
rule m2319_4b1a97a1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.4b1a97a1c2000b12"
     cluster="m2319.4b1a97a1c2000b12"
     cluster_size="8"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker script html"
     md5_hashes="['090d9c2a23f1fcf59eed5140b4acc03f','0ab21f8eadff637d925a412cf5fdcd7d','902f6d574a50ce6522c826263bbaeb33']"

   strings:
      $hex_string = { 4156302f4f59396d383137666d79492f73313630302f494b4c414e2b5345524942552e6769662220626f726465723d223022206865696768743d223135222077 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
