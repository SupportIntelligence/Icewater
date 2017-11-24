
rule k2321_2914e96994bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2914e96994bb0b12"
     cluster="k2321.2914e96994bb0b12"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['0444f4967b663b2aa7fe08515f5bdf73','64c8c824b221c67f7667b927ac6da995','e6f65f57ea0d7ccf101e1d3a95f11b32']"

   strings:
      $hex_string = { 496b664aaa67882b734595d3847533f8f5b9dcb353d85f0ff7ddd687312d560cd3b4fe3aa9540263f9dc76f0107059423e572a93eafcfd7b8606cc4890bed49f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
