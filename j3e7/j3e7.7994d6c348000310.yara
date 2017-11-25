
rule j3e7_7994d6c348000310
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7994d6c348000310"
     cluster="j3e7.7994d6c348000310"
     cluster_size="101"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos risktool"
     md5_hashes="['00270ed3b2dded92cffa57df76779821','00466044255150dab7411803981d4c4d','202af11cde07bbc343f9206ca6397199']"

   strings:
      $hex_string = { 0d676574506172656e7446696c6500076861734e6578740004696e666f0006696e766f6b6500086974657261746f7200106d416c6c4170706c69636174696f6e }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
