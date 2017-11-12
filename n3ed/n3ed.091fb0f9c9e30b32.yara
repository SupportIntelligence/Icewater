
rule n3ed_091fb0f9c9e30b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.091fb0f9c9e30b32"
     cluster="n3ed.091fb0f9c9e30b32"
     cluster_size="315"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['01afea03faede8ea2a149375fe13cac8','027777c3e1e46b9e745b710459c77bc8','24214721478cdfa228d23f663e113d14']"

   strings:
      $hex_string = { 3c3075040bc9eb022bc88d45d050ff75145157e8686b000083c4103bc37404881eeb588b45d4483945e00f9cc183f8fc7c2d3b45147d283acb740a8a074784c0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
