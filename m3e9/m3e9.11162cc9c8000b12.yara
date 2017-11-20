
rule m3e9_11162cc9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.11162cc9c8000b12"
     cluster="m3e9.11162cc9c8000b12"
     cluster_size="20"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus vbna pronny"
     md5_hashes="['152cad93e7ad93a5d40d3302ee4de64b','4a87c97a44314cd5f87b56fe4b8a57cc','e68b4b080a8562f03d9a6fca1a96d871']"

   strings:
      $hex_string = { 6c448197999abbc2bed5cacac6fcdafbfcfbfcfbf25d820338fd0000000000000000000000001bdf865b5b87678b8d8f4d567d7e929396989cb4b5b59f48c5d8 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
