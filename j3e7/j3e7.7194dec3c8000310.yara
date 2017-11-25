
rule j3e7_7194dec3c8000310
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7194dec3c8000310"
     cluster="j3e7.7194dec3c8000310"
     cluster_size="37"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos risktool"
     md5_hashes="['0515287c724a5e56908b1b9bee0d6355','1443c1efb7b69698029f75e588d9d73c','6b22d4ecc145a50159259019d5daaad2']"

   strings:
      $hex_string = { 0d676574506172656e7446696c6500076861734e6578740004696e666f0006696e766f6b6500086974657261746f7200106d416c6c4170706c69636174696f6e }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
