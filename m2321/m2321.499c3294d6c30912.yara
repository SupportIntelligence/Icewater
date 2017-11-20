
rule m2321_499c3294d6c30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.499c3294d6c30912"
     cluster="m2321.499c3294d6c30912"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="elemental elementa jtvn"
     md5_hashes="['2923fae544ef7cd31d24a0fc50be7194','440718c24bfba85d69dd2d3331f031b0','adb152b17f5d599ed975bb2746b37e1d']"

   strings:
      $hex_string = { 2054d3b9887930dfff27cd7ae3f484122d06a03b1ef6b15b4e9a29071797cfcfb339c896926780601a775d242febb40e8f47d138febdca4bf26683e89e8a7c82 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
