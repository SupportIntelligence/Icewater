
rule m3e9_29056466c5410b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.29056466c5410b32"
     cluster="m3e9.29056466c5410b32"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi vobfus wbna"
     md5_hashes="['07adbb209b969daa7272088a8b7f19c0','2bfce77e3d033df78c534ceaf455964b','bed989e18e6e3fc060ee2a568d5c3b97']"

   strings:
      $hex_string = { f2fc9ef1fe98ebfbb0f8ffc0e3f63188a64c9bb353a3bc5bacc465b6cb60bbd371c5da67c6dd6acde568d0ea68cfe870cee46cd7ee65d4eca4e7f68fe2f18edb }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
