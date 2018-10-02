
rule m26bb_478617e6ee400912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.478617e6ee400912"
     cluster="m26bb.478617e6ee400912"
     cluster_size="311"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="nemesis adwaredotdo dotdo"
     md5_hashes="['026d80b285d61f6c2259418f70dc089871fd2775','c4fb6aa3440997d515468fa05a773a291925780e','1cbeae4dff790eaa42de78c294046ee16bb158b4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.478617e6ee400912"

   strings:
      $hex_string = { 48e1ff0448e0ff0547dfff0646ddff0844daff0940d7ff0b3bd2ff0d36ceff0f31c8ff102cc3ff1026bcff1323b6ff2d2eb2ff5241b1ff5c45aeff4234a5ff3e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
