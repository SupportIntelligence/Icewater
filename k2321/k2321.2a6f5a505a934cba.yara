
rule k2321_2a6f5a505a934cba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2a6f5a505a934cba"
     cluster="k2321.2a6f5a505a934cba"
     cluster_size="12"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy backdoor"
     md5_hashes="['05f04bb62a48c81506e7b8599dd9ee61','1249ed88a19a864df35a18f9b830dd8f','ed8e886f4ebe9408286f2b08da0205df']"

   strings:
      $hex_string = { b629c08f49b72779f6daf191379e7826afa083c582b0624306c9dbbfe3875d086ef01c52fefd3e01f7fc0d95d088489d32efd5b14a049723d803c271794ce756 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
