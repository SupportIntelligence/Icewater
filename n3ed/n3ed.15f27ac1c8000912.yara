
rule n3ed_15f27ac1c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.15f27ac1c8000912"
     cluster="n3ed.15f27ac1c8000912"
     cluster_size="18"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bmnup"
     md5_hashes="['06541f582e1c87f1feb54825b096e99e','2960ea2d12bfd33da71df6a08ea99e3d','cdbe3e3973dc672507c4d2f6f078b3f7']"

   strings:
      $hex_string = { 3c3075040bc9eb022bc88d45d050ff75145157e80136000083c4103bc37404881eeb588b45d4483945e00f9cc183f8fc7c2d3b45147d283acb740a8a074784c0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
