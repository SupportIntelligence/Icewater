
rule k2321_69349646dbbb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.69349646dbbb1912"
     cluster="k2321.69349646dbbb1912"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="adload nsis bundler"
     md5_hashes="['3a42b03e252864e6388b4f72ca54e93a','3e0a86f052f2519228d88d426cb62059','d957d15d21af4d75ad54b4b08ce475fe']"

   strings:
      $hex_string = { 7cacefcef43e4a8093185fbcb3809e13d4402806505eed15b0169c17580bc772f2bbeb74adcd71842b754310c631a7359f89e23d69add69d1446a98ab30f8e86 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
