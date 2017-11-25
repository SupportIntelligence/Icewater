
rule j3e7_7514d6a348000110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7514d6a348000110"
     cluster="j3e7.7514d6a348000110"
     cluster_size="5"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos piom"
     md5_hashes="['6b8608e798f483d85bb2fe53a8715d5e','7a7c5a71f4aca4a29b3827ea2e705479','b50f59be853f5bc96a7dde9c06b70905']"

   strings:
      $hex_string = { 7954687265616400066578697374730007666f724e616d650003676574000f6765744162736f6c7574655061746800126765744170706c69636174696f6e496e }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
