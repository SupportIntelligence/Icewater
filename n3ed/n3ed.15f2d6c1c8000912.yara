
rule n3ed_15f2d6c1c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.15f2d6c1c8000912"
     cluster="n3ed.15f2d6c1c8000912"
     cluster_size="126"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bmnup"
     md5_hashes="['0bac9349afb1f639a9b134f2f4d7f1a9','1975a85d90d65e0b02b6b8e6413973d8','69f79efe3b22347ae8ab78647c48ed05']"

   strings:
      $hex_string = { 3c3075040bc9eb022bc88d45d050ff75145157e80136000083c4103bc37404881eeb588b45d4483945e00f9cc183f8fc7c2d3b45147d283acb740a8a074784c0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
