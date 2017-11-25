
rule p3e9_519afcc9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.519afcc9c4000b12"
     cluster="p3e9.519afcc9c4000b12"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur malicious"
     md5_hashes="['a843a4f294ccbedcf91addf750cdb9fa','b3552a16657b6f747ce334a87704047e','ececeb3a941f3e1e42fed5fb29aad229']"

   strings:
      $hex_string = { 8000000380000003c0000003e0000003e0000003f0000003f8000003f8000007f800000ff800001ff800003ff800007f0000010001002020000002002000a810 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
