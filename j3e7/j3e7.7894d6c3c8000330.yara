
rule j3e7_7894d6c3c8000330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7894d6c3c8000330"
     cluster="j3e7.7894d6c3c8000330"
     cluster_size="348"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos risktool"
     md5_hashes="['00eb30ce51dfba77244fa30598cf57ce','0130a3a3d16bd07f50f002ed9a00bac2','06c75852c2fc21b33f5e58f3c66e23f4']"

   strings:
      $hex_string = { 0d676574506172656e7446696c6500076861734e6578740004696e666f0006696e766f6b6500086974657261746f7200106d416c6c4170706c69636174696f6e }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
