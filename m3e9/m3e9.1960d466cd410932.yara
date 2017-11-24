
rule m3e9_1960d466cd410932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1960d466cd410932"
     cluster="m3e9.1960d466cd410932"
     cluster_size="148"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys aiqh"
     md5_hashes="['024b434bb8a26b52d7c59a4bd21eec54','0990505fee25207c8dc457912530720e','33739e309a21faab4f7491753cccb421']"

   strings:
      $hex_string = { 010c194a220d1212101345445260627761875b4546638e9191bbcacabc9dbbe0edfbfffcfcfbfbfaf4a7000000f4fcfc03131f1e1d1d1d1e43475472737c7e8a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
