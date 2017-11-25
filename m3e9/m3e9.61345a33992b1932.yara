
rule m3e9_61345a33992b1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.61345a33992b1932"
     cluster="m3e9.61345a33992b1932"
     cluster_size="20"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus vbkrypt diple"
     md5_hashes="['0eb64615cfcb29ef3f1c396fd448f90c','1d0be1dd497f04bbff8e603ab3bcdb36','c7370eeb0b0edcba6c0091df9f471231']"

   strings:
      $hex_string = { 0c050567bdbfba6dba8887861b0254d7f6f7f9f7f6cc5626000000037b767a81b7cac1c9c0cabe3c282a2a2b2827290c2a052d67bbb36e6d674c4c4b111857d4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
