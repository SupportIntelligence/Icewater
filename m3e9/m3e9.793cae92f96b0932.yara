
rule m3e9_793cae92f96b0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.793cae92f96b0932"
     cluster="m3e9.793cae92f96b0932"
     cluster_size="26"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus chinky wbna"
     md5_hashes="['07a116db0793bd699286038d1ba75d49','086d2cb4a419fb034c5cdc15e7f14415','b96ad30095517910caaecbcad752eef7']"

   strings:
      $hex_string = { 054ab77a79746354898d120260caf6f3f6f3f1c7463f00000003858585b2bfbec0c1cacab93c262222090909090505053b707a7a79745d504c4b0c0764def6f3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
