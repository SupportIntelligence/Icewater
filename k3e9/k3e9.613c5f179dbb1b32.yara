
rule k3e9_613c5f179dbb1b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.613c5f179dbb1b32"
     cluster="k3e9.613c5f179dbb1b32"
     cluster_size="24"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['0c50f4dc34818da2c6a49841d015198e','1dd99f8cbfa5d61e98f4412e23669586','c18e39324446b94b92d8df43a7e6fb5e']"

   strings:
      $hex_string = { 8d4a0c89480889410483649e440033ff4789bc9ec40000008a46438ac8fec184c08b4508884e437503097804ba000000808bcbd3eaf7d22150088bc35f5e5bc9 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
