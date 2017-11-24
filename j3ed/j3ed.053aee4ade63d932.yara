
rule j3ed_053aee4ade63d932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3ed.053aee4ade63d932"
     cluster="j3ed.053aee4ade63d932"
     cluster_size="13"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor malicious atraps"
     md5_hashes="['03d6dad6b05488f64e7efa30ac68d156','08b75e0a81b447608c00bae79f2b8b40','f71504511d67209d923b3a9f717d72ed']"

   strings:
      $hex_string = { 1033d242d1e281c2b4f1c90103c22bd28d8200bdffdb0503930034b96054818d50890c248b0c2481e9f5ee0e1f518f0424505a8f0040c742047fda99b348836a }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
