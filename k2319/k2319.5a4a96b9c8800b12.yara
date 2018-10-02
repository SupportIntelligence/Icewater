
rule k2319_5a4a96b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5a4a96b9c8800b12"
     cluster="k2319.5a4a96b9c8800b12"
     cluster_size="119"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['94950cbf54afb507280d70ca3f71a626177d6e78','249dfb3bdc4da86b1e79aaf791c6b91052f5df85','f66eca203d0a8334a3c5093bc08718322486b94c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.5a4a96b9c8800b12"

   strings:
      $hex_string = { 6b7d3b666f7228766172206f396a20696e20743651396a297b6966286f396a2e6c656e6774683d3d3d28307834453e28307841372c3078313038293f3139323a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
