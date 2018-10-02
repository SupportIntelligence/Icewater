
rule m26bb_619c3ac1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.619c3ac1cc000b12"
     cluster="m26bb.619c3ac1cc000b12"
     cluster_size="135"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="allaple rahack malicious"
     md5_hashes="['d7cda08b25beb185536c6a612280abe70ca6f9d6','e496f139c401842f217e30a5f6512983192c808f','7aaaf6351d7ebd6a81711731406cef831b7c1759']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.619c3ac1cc000b12"

   strings:
      $hex_string = { 6bbf4d4b2ac06fe8a526dfde22e435684ce5208a50a8724cf8a985a2b7a4e3e66db9d9f29421c5b17a71b5b87ef136dd043dda8cee49c8c1299a7c0dea31baf0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
