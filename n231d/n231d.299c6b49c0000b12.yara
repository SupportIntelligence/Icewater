
rule n231d_299c6b49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.299c6b49c0000b12"
     cluster="n231d.299c6b49c0000b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hiddenapp androidos riskware"
     md5_hashes="['28456fe88afd5a412b0df59cf0c9437df4fc0e89','142e8470c160e8ead2562475cda179c5d7c2398d','ce6d6dae87e9f509b2b12f3f51e30ac89ba964c0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.299c6b49c0000b12"

   strings:
      $hex_string = { 6018863f73e68c0363bb758d228194019f931270fefc799bd2248820081415174fca11330c8382c242d4ac59132c550909feae5dd8b87123788e835eabc3a953 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
