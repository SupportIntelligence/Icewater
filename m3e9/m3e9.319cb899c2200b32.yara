
rule m3e9_319cb899c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.319cb899c2200b32"
     cluster="m3e9.319cb899c2200b32"
     cluster_size="38"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul krap"
     md5_hashes="['198a28f90532038d490e14ba503d9a88','1e1e610630bf3b0af2dbb167afa7e879','cce4aec0d1693b08144a3e22cedcc8dc']"

   strings:
      $hex_string = { ca742a44ada00401874695820fb051654c1299e819aa1000d2defa7f6b0e9bd926033c135d0df4767a9a75c240e07c174bb49dd98f1ee4cf89c78bda2ff55b32 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
