
rule j3e7_7194d6c3c8000330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7194d6c3c8000330"
     cluster="j3e7.7194d6c3c8000330"
     cluster_size="373"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos shedun ebzlbe"
     md5_hashes="['0158726c78856edc3763107b30532170','0214b4430d36ca32c92b825cffd1d8f3','08487500af64ad171356bbd7208f9969']"

   strings:
      $hex_string = { 0d676574506172656e7446696c6500076861734e6578740004696e666f0006696e766f6b6500086974657261746f7200106d416c6c4170706c69636174696f6e }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
