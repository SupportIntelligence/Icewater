
rule o3f1_311a9cc1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f1.311a9cc1cc000b12"
     cluster="o3f1.311a9cc1cc000b12"
     cluster_size="36"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos riskware"
     md5_hashes="['03b87bcd31f3c4bbd46b959b29b6d2cc','05908b86de33f29eb7d208196da89936','724a972a679a9f5facbba6c806a1fe85']"

   strings:
      $hex_string = { 72e0b3165d003fd378e9f373af21de332b5ecc059a8775fb7997c283bb4baca4a90ec61459b8b1a292d0c93b1930cdcb259f6ee9240a18870f91db3902511f12 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
