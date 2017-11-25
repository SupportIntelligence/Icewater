
rule m3e9_61344a23992b1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.61344a23992b1932"
     cluster="m3e9.61344a23992b1932"
     cluster_size="115"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus vbkrypt autorun"
     md5_hashes="['01abc19f325c00498a254922959b172f','09b9e27dc1f8a70ce8bb22e0d68e6dff','680feacd77cf7960bb6f14ba1cdbd061']"

   strings:
      $hex_string = { 0c050567bdbfba6dba8887861b0254d7f6f7f9f7f6cc5626000000037b767a81b7cac1c9c0cabe3c282a2a2b2827290c2a052d67bbb36e6d674c4c4b111857d4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
