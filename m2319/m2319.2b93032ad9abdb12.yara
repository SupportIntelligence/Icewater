
rule m2319_2b93032ad9abdb12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b93032ad9abdb12"
     cluster="m2319.2b93032ad9abdb12"
     cluster_size="5"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['7b549b4792c37034f95775534930d34f','7d09f22743577efd8f33d641d0442e31','eef75b98481c0974d3b7a798f57c8dcf']"

   strings:
      $hex_string = { 2e636f6d2f7265617272616e67653f626c6f6749443d39373330373934303633343136393138313826776964676574547970653d506f70756c6172506f737473 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
