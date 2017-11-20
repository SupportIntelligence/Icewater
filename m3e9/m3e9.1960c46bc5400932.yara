
rule m3e9_1960c46bc5400932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1960c46bc5400932"
     cluster="m3e9.1960c46bc5400932"
     cluster_size="131"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys aiqh"
     md5_hashes="['02fcaf083e155e7682c66b4defd42184','03f280bc42d2b16dbe0a453567bbac53','98cb263e2aaa758edac512a89628cb1e']"

   strings:
      $hex_string = { 0c194a220d1212101345445260627761875b4546638e9191bbcacabc9dbbe0edfbfffcfcfbfbfaf4a7000000f4fcfc03131f1e1d1d1d1e43475472737c7e8ad6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
