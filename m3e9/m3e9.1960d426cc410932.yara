
rule m3e9_1960d426cc410932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1960d426cc410932"
     cluster="m3e9.1960d426cc410932"
     cluster_size="132"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys aiqh"
     md5_hashes="['052d93d9b335b8314d7b0e81bb03a0fc','11b3856713e6a381af5986bf96ea28b2','91a69cfbfcacbeff27120c3c27c61088']"

   strings:
      $hex_string = { 010c194a220d1212101345445260627761875b4546638e9191bbcacabc9dbbe0edfbfffcfcfbfbfaf4a7000000f4fcfc03131f1e1d1d1d1e43475472737c7e8a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
