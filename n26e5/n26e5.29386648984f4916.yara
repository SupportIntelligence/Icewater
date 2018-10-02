
rule n26e5_29386648984f4916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26e5.29386648984f4916"
     cluster="n26e5.29386648984f4916"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="pemalform riskware malicious"
     md5_hashes="['cdfed0ffaea473aa6339fec072ab4adc64b4f21a','ce247a282d20ab41215e94be5f9d87afde8e4031','d751dd419399c8e9ab8883c5dbcdf644894b6fa6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26e5.29386648984f4916"

   strings:
      $hex_string = { 1c6a0153e871b0fbff8b470483c4188b4d0c85c07404488947048b450889088b4df464890d00000000595f5e5b8be55dc208008b41043b48087505897808eb02 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
