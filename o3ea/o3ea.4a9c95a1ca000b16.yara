
rule o3ea_4a9c95a1ca000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ea.4a9c95a1ca000b16"
     cluster="o3ea.4a9c95a1ca000b16"
     cluster_size="1273"
     filetype = "application/java-archive"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos riskware smspay"
     md5_hashes="['002dd9fd3a2192b6d3661240e3469c5c','00abf0f5a2ef4da26e8c3dd61fb2be13','026d558c9d38609cc5cf282b09f9f934']"

   strings:
      $hex_string = { df2c01f974d47bdadda232edce6fd8bbd05edb7d169e4d4f5b615168af3eee7e556c501af7a76a843aef463953f2ec97cb64983db99b592b630da18f08a509ae }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
