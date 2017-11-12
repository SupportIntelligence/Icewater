
rule k3e9_6a1eb949c8000b00
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6a1eb949c8000b00"
     cluster="k3e9.6a1eb949c8000b00"
     cluster_size="49"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob vetor"
     md5_hashes="['43191f9cb41a2a8b3a88bd0c87c3ef85','4e86d4ea5baa138e596515da9885f19e','ee4f0851942b3365894d618c0db00b7e']"

   strings:
      $hex_string = { 71d0118b1a00a0c91bc90efbbe3b05bab3d21193580000f875ae17f88cc86e1ba4d21193490000f875ae17811e87343ad3d21192c700c04f68d5ae9c9f799769 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
