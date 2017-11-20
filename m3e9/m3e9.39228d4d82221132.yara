
rule m3e9_39228d4d82221132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.39228d4d82221132"
     cluster="m3e9.39228d4d82221132"
     cluster_size="31"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys malicious"
     md5_hashes="['a1949bb433609c660b7a3662480d3e3a','a7fd16820b686f178e87d414796fa335','c124ccec59b02cf734bc30a19ded26a0']"

   strings:
      $hex_string = { 010c194a220d1212101345445260627761875b4546638e9191bbcacabc9dbbe0edfbfffcfcfbfbfaf4a7000000f4fcfc03131f1e1d1d1d1e43475472737c7e8a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
