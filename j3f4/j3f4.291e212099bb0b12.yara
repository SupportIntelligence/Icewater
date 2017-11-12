
rule j3f4_291e212099bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f4.291e212099bb0b12"
     cluster="j3f4.291e212099bb0b12"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386 Mono/.Net assembly"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious dotdo engine"
     md5_hashes="['5de3e2c6c0ac3c28539c4625427c7db2','6034bd4b6a3807d365c59e8ccece9d03','bf440ae5cbfe1ef306c6374c9721f200']"

   strings:
      $hex_string = { 3c737570706f727465644f532049643d227b31663637366337362d383065312d343233392d393562622d3833643066366430646137387d222f3e2d2d3e0d0a0d }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
