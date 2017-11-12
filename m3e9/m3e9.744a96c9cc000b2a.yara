
rule m3e9_744a96c9cc000b2a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.744a96c9cc000b2a"
     cluster="m3e9.744a96c9cc000b2a"
     cluster_size="23"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shodi prepender virut"
     md5_hashes="['3c39fe2d529c85aa91fd36e0e51974f5','4162bd8408182c67cf83600b4ab3b384','f1297dedc7f6bc1b0499546dcda5dfb3']"

   strings:
      $hex_string = { 3bd18d85fcfeffff730f8a1080fa227403881747403bc172f18027005e5fc9c20400558d6c248881ec94000000576a245933c08d7de8f3ab8d45e450c745e494 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
