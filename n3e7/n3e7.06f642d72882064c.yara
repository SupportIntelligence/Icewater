
rule n3e7_06f642d72882064c
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.06f642d72882064c"
     cluster="n3e7.06f642d72882064c"
     cluster_size="11"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="speedingupmypc malicious optimizerpro"
     md5_hashes="['164e8ccf6f72bb56850d18c0b3b8918c','19eff83f7c1b14b1191f35c523bcebeb','ffdc04b3f177aaa6504dd2ad9a291224']"

   strings:
      $hex_string = { 1e25c9fa83951bcff7eedfc2248b9e4104e40bd5c0c6875e619c752730720df5a4bc8c92a7132ab41f62a80a1991bfe32f68523aae8fb37358697c7467366a60 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
