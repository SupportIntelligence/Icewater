
rule m3e9_5b3a930cbb63d912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5b3a930cbb63d912"
     cluster="m3e9.5b3a930cbb63d912"
     cluster_size="1567"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hotkeyshook keylogger dabc"
     md5_hashes="['0000906f466b9c616e974193e2789edc','0024dfdfa1392b8b54927a2bf564133f','024da209aec6c6c1d7b9f3631ed88015']"

   strings:
      $hex_string = { 6a02ff55505d8b4e208d56285257ff761c8b016a01ff50508b075b8946245f5ec3558bec515153568bf18b4508578b4e248b7e288d5e282bf903c7837e080089 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
