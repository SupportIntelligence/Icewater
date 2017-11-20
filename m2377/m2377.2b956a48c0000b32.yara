
rule m2377_2b956a48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.2b956a48c0000b32"
     cluster="m2377.2b956a48c0000b32"
     cluster_size="5"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['2e65c19bc4f91599eeb8f78f78c5e298','5626769faa1d0f3ba8b961dbd0f5997b','f670658fc96b831aede12c19c9dbcc0a']"

   strings:
      $hex_string = { 8322dd652a92accc08571b7393993554da694a5f5c7c0e6e58d3e854b18137bb0f251fe63245f106bea2863e07ca29c474a9dbb851dcc0d22c6c004634b5568f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
