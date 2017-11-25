
rule m3e9_134eba49c8010b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.134eba49c8010b12"
     cluster="m3e9.134eba49c8010b12"
     cluster_size="56"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore riskware click"
     md5_hashes="['052566e7c19b83e082d189db3947668b','06236251c8ac1ebe6ceb7865516c6090','4c154d84b0185e36548124c01952b448']"

   strings:
      $hex_string = { bbdb5a88225db9ed7e82659012b1d38b3dbfe41ffc3677e67050a88df6043c61bc13aa67109aee5f8ca72a73e5362f5ee7ba694042b59b86c4309f7c47665559 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
