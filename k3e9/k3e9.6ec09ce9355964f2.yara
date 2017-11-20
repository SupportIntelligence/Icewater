
rule k3e9_6ec09ce9355964f2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6ec09ce9355964f2"
     cluster="k3e9.6ec09ce9355964f2"
     cluster_size="33"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mywebsearch mindspark webtoolbar"
     md5_hashes="['01f205cb070f6b41eb1cadf24258d149','15228bf32161a0da60347ab8b62539db','8d458f6ba7848c623c69a4d38734a497']"

   strings:
      $hex_string = { 67e6ad77605f0056b518e9f216a04bb37f1e2ee2463235a9998687ca54eaeb49413d04319d2819bde0057cbf426521a38394854cf070c663f1f30b512c1dbc25 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
