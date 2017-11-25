
rule j3e7_7114d6a348000330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7114d6a348000330"
     cluster="j3e7.7114d6a348000330"
     cluster_size="227"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos ebzlbe"
     md5_hashes="['01508faa00fe519dae9440f3f551665f','01fee1cb409db7d134f9f1c139f09ab7','17c9f617f79fd39148765d63b565fdb1']"

   strings:
      $hex_string = { 696f2f496e70757453747265616d3b00164c6a6176612f696f2f4f757470757453747265616d3b00134c6a6176612f6c616e672f426f6f6c65616e3b00104c6a }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
