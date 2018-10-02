
rule m2319_3b395972d922e111
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3b395972d922e111"
     cluster="m2319.3b395972d922e111"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="inor script faceliker"
     md5_hashes="['7eb4094bf6c0039c19fd81b0deff0690f47f7058','9e7d54d732ea3344b970e447dc1f13c436842a9a','532e2538092ac06a58b9bb789749868ee94e7de6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.3b395972d922e111"

   strings:
      $hex_string = { 312f672c2222293b696628212f5e5b2d5f612d7a412d5a302d39232e3a2a202c3e2b7e5b5c5d28293d5e247c5d2b242f2e74657374286329297468726f772045 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
