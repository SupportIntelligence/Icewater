
rule o26c0_539eea44c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.539eea44c0000b12"
     cluster="o26c0.539eea44c0000b12"
     cluster_size="111"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="strictor malicious startsurf"
     md5_hashes="['09ef1d006a22c8c8892f918a9d991be846bd0505','3c8b35c2a53c42e03cdba3f1c9d01de1e2cf9255','35dba8d211f3ae34dadf8000f364c20675d63cc5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.539eea44c0000b12"

   strings:
      $hex_string = { c26a2083e01f592bc8d3cf33fa873b33c05f5e5b5dc38bff558bec8b4508578d3c85b0b55c008b0f85c9740b8d4101f7d81bc023c1eb57538b1c85d8dc400056 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
