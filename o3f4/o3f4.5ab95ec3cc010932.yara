
rule o3f4_5ab95ec3cc010932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f4.5ab95ec3cc010932"
     cluster="o3f4.5ab95ec3cc010932"
     cluster_size="3150"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="msilperseus hacktool idlekms"
     md5_hashes="['00036b63c919d27fe38a82ce50d95dae','00222195fbe5c4258ab9043bf0905065','010c75961f1968d4490d6eba5c49f4e6']"

   strings:
      $hex_string = { 0f148905b941c11dc902c1415415e103fc33d51da105d541cd118904df41bb13a9051b0333003100f941e71d51001242ed1d51011b03f31db9052c424c1e6101 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
