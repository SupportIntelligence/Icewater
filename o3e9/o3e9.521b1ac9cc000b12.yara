
rule o3e9_521b1ac9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.521b1ac9cc000b12"
     cluster="o3e9.521b1ac9cc000b12"
     cluster_size="13"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur polyransom"
     md5_hashes="['2b3a00a1af89fe91d96a23b44177c088','98a6e0aef786a17ae7fa01d441f8940e','d7d410e72466716d8934f4d202078d14']"

   strings:
      $hex_string = { 1c3dd0ff2149dbff2754e5ff2a5cedff2b5deeff2856e8ff234cdeff1d40d3ff7b6386fffee3c8fffcd1beffdd978bff331a0d8c351b0e3c3f1b1b0e7f7f7f01 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
