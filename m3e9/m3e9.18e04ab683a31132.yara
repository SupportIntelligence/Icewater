
rule m3e9_18e04ab683a31132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.18e04ab683a31132"
     cluster="m3e9.18e04ab683a31132"
     cluster_size="14"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="barys vbna wbna"
     md5_hashes="['0a4bfb20516e53abc5ae07a95d5e6efb','1cd7db692560aa72a5ee42e314b841e7','de2cc53c7ee33309553ec3f540396f1e']"

   strings:
      $hex_string = { 151f272953595a5a617b89894f4b62958e94a1a3a3a2b6c8d7e9f0fffffffffcfbf5b1000000f6ffff02101e121c1d1c204d546061767a80a9c5d2ccbebfc1ce }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
