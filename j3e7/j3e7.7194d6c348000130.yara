
rule j3e7_7194d6c348000130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7194d6c348000130"
     cluster="j3e7.7194d6c348000130"
     cluster_size="93"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos risktool"
     md5_hashes="['02eb3c76a8c855bcb8d67b9a9992b020','04916695439f608e9667290e12f8390f','2887ce452dd9dccee14e538f84e6faff']"

   strings:
      $hex_string = { 0d676574506172656e7446696c6500076861734e6578740004696e666f0006696e766f6b6500086974657261746f7200036a617200106d416c6c4170706c6963 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
