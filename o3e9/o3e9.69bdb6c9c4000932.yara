
rule o3e9_69bdb6c9c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.69bdb6c9c4000932"
     cluster="o3e9.69bdb6c9c4000932"
     cluster_size="21"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock krypt nabucur"
     md5_hashes="['5e3bbcdb967ce69d18caad4efb3b43db','917e5196b5b6afe2f50033b0bfe0eaaf','d134c5cfa01c29d727311af424eae426']"

   strings:
      $hex_string = { e0892000df963b00d97d0100da7f0300da7f0300db7f0300db7f0300da7f0300da7f0300da7f0300d97e0300d97d0300d97e0300d97d0300d97e0300d97e0300 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
