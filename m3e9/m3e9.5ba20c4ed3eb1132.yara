
rule m3e9_5ba20c4ed3eb1132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5ba20c4ed3eb1132"
     cluster="m3e9.5ba20c4ed3eb1132"
     cluster_size="62"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus jorik malicious"
     md5_hashes="['003a4e1db0bda1289a2ee32adcabb2ff','060b69cb1cee5e8fa05b9545e6a4a92f','a226bb39239b26674f83c0a30ae7ba77']"

   strings:
      $hex_string = { 430c8bd68bc7e8a7ccf9ff33c05a595964891068d27e51008d45f4e8f229efffc3e9d81fefffebf05f5e5b8be55dc2080090558bec83c4f853565733c9894df8 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
