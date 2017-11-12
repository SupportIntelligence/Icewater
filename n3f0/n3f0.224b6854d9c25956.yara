
rule n3f0_224b6854d9c25956
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f0.224b6854d9c25956"
     cluster="n3f0.224b6854d9c25956"
     cluster_size="58"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mira uymi icgh"
     md5_hashes="['2cc6b300b45217c52d1d088ba921012f','3abad14374a11f4264f9c0d311a1f20c','cb5bcf5dd0c1c80e40f633aab84a2e7c']"

   strings:
      $hex_string = { 3dc55d3b8b9e925a0d65170c7581867576c9484d65ccc6910ea6aea019e3a346bcdd8ddef99dfbeb7eaa51436fc6df8ce980c947ba93a841bf3cd5a6cfff491f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
