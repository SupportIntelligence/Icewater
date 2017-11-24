
rule n3e9_4316bc49cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4316bc49cc000b12"
     cluster="n3e9.4316bc49cc000b12"
     cluster_size="87"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus chinky diple"
     md5_hashes="['003d16118fba95700c749bc92ad86767','1270f40134663417bdb4c876a2bfd3fd','a3633fffc1ece2af91b1c8631269f1af']"

   strings:
      $hex_string = { c9f2f5d9cabfbeb578ae939a8b2d41b6d6f4f5f4f5f4cb4a2e0000001234343051c0cacad9dbf0d935060a0a2f3234404572cad6cabbb575787394978c2d2767 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
