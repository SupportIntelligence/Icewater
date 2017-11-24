
rule m3f0_531ba9e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f0.531ba9e9c8800b12"
     cluster="m3f0.531ba9e9c8800b12"
     cluster_size="874"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mira heuristic icgh"
     md5_hashes="['0019c29ebdad4aa25926d897c9d9ca1f','001a2d3a279c0a570b02095cef09b678','085dee2dadabdafadd4dd2c7137324ff']"

   strings:
      $hex_string = { f0c0146c71a5fc648d55a8fa1018c5d0c7bfd4619a1f20ccc46ea190b7e0ff878eeb4601c94a780e807c2aa841a209cb1a07fe63fb79f2833b3c3289d849b924 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
