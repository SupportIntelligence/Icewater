
rule k2319_525a94b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.525a94b9caa00b12"
     cluster="k2319.525a94b9caa00b12"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['49ba32f0e4778fb72dd80b62221037b1d0db4255','f87f9bfe0bd5666dd2c3667dc75dabfd63319f6f','057119dcad82af5d072177cc3ae3e761c738edf3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.525a94b9caa00b12"

   strings:
      $hex_string = { 646f773b666f72287661722058304e20696e20533075304e297b69662858304e2e6c656e6774683d3d3d282830783133342c32382e364531293e30783143343f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
