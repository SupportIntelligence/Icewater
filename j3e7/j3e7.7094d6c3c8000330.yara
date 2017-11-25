
rule j3e7_7094d6c3c8000330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7094d6c3c8000330"
     cluster="j3e7.7094d6c3c8000330"
     cluster_size="539"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos shedun risktool"
     md5_hashes="['008f4fe75025324ac32612eb56fec421','01bf12ede2d62ae4afe03177c6398739','094b94ca089a41afe5372b804a18e212']"

   strings:
      $hex_string = { 0d676574506172656e7446696c6500076861734e6578740004696e666f0006696e766f6b6500086974657261746f7200106d416c6c4170706c69636174696f6e }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
