
rule k2321_69349606dbbb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.69349606dbbb1912"
     cluster="k2321.69349606dbbb1912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="adload installmonster bundler"
     md5_hashes="['3af3c14f5cd1f2871fb3691ba69cdb21','bc1696af27db2278b152cb6ca25f2d7f','e0e4c6723b31cdd77187ed1f7010d2ec']"

   strings:
      $hex_string = { 7cacefcef43e4a8093185fbcb3809e13d4402806505eed15b0169c17580bc772f2bbeb74adcd71842b754310c631a7359f89e23d69add69d1446a98ab30f8e86 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
