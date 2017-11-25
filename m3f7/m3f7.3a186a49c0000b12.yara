
rule m3f7_3a186a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.3a186a49c0000b12"
     cluster="m3f7.3a186a49c0000b12"
     cluster_size="9"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker html"
     md5_hashes="['0c7a3540cacdb8433ecf7ca541c97e15','1c9fa47194806066744a1c61f6aafe6d','d6c351c0c257034fa732e730124ebdbf']"

   strings:
      $hex_string = { 7b436c69636b4a61636b46624869646528293b7d293b0a0909096a517565727928222e726174696e67626c6f636b22292e6d6f7573656f7665722866756e6374 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
