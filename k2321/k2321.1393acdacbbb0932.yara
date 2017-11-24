
rule k2321_1393acdacbbb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.1393acdacbbb0932"
     cluster="k2321.1393acdacbbb0932"
     cluster_size="26"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androm backdoor symmi"
     md5_hashes="['0cbee0ff53789e7f4b889513114e04a3','0ff570c9a8ed7adaa1f24f7fa915c540','ae7b79f3713f56ecaafad32878ee3467']"

   strings:
      $hex_string = { 192df40f652f1ce52597afaea07328117fc51bc11a20d808760afd5d5200f56d41e09e62a29db3c685743cbaa1071309d1ad14354a9f8627aafc1fca53935405 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
