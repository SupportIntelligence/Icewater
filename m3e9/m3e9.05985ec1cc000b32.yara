
rule m3e9_05985ec1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.05985ec1cc000b32"
     cluster="m3e9.05985ec1cc000b32"
     cluster_size="23153"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['000e1a5ec6dac8e58a93df1b49ea9bbc','001492ae5d2326b8d8f02815560903a7','005ade9ff7a049a1b124a24e0be770b0']"

   strings:
      $hex_string = { 4dfc8b0989088a0b8848048345fc0446433bf77cb733dba160e700018d34d8833eff754d85dbc646048175056af658eb0a8bc348f7d81bc083c0f550ff15d010 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
