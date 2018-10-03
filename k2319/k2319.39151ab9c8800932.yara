
rule k2319_39151ab9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.39151ab9c8800932"
     cluster="k2319.39151ab9c8800932"
     cluster_size="28"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['a9c875515698cee597d4d652095f98ded793fc91','b41db2a03e3e27628176e3b76856b7b87df4e882','ffdc1b6e57162f5b22eca5d4771e22bb2e20bf15']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.39151ab9c8800932"

   strings:
      $hex_string = { 627265616b7d3b666f7228766172206d304a20696e20593657304a297b6966286d304a2e6c656e6774683d3d3d282830783146432c312e3438394533293c3078 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
