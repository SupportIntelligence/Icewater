
rule j3f4_291f216118bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f4.291f216118bb0b12"
     cluster="j3f4.291f216118bb0b12"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious dotdo engine"
     md5_hashes="['2f44ac740b7f2ad4cc6f46ccec24f084','3f364d0b88bd94be1c1eca997acfe6f4','7bac527e7789f95ec9c52cbaf38623af']"

   strings:
      $hex_string = { 3c737570706f727465644f532049643d227b31663637366337362d383065312d343233392d393562622d3833643066366430646137387d222f3e2d2d3e0d0a0d }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
