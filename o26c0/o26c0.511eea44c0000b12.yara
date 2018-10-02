
rule o26c0_511eea44c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.511eea44c0000b12"
     cluster="o26c0.511eea44c0000b12"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="strictor malicious genkryptik"
     md5_hashes="['136683fafae4d00d099037591ffecc40023a80e7','da970c8c3c107879cc9c92a1bf01624bc292beaa','725223532c85a357d5e9aafa05784b75137306c5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.511eea44c0000b12"

   strings:
      $hex_string = { c26a2083e01f592bc8d3cf33fa873b33c05f5e5b5dc38bff558bec8b4508578d3c85b0b55c008b0f85c9740b8d4101f7d81bc023c1eb57538b1c85d8dc400056 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
