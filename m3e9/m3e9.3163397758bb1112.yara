
rule m3e9_3163397758bb1112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3163397758bb1112"
     cluster="m3e9.3163397758bb1112"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['4ef13375eec2ba66d72bade848660a95','5fba9c448a4aa9dc4e10b9c05ddad9c7','e830b2bf2abf6090224a473d31e0a8a6']"

   strings:
      $hex_string = { d2923dfad6975eebb5a7b1f074b6f1fd54b2f9ff479bedff3a85e9ff316be4ff2956d8ff2d4fc6f8727dadaeecd3b776d1995cffce944effca8e3efec89035f3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
