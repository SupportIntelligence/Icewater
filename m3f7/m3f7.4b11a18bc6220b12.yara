
rule m3f7_4b11a18bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.4b11a18bc6220b12"
     cluster="m3f7.4b11a18bc6220b12"
     cluster_size="24"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker html script"
     md5_hashes="['05f3b3ae428e5d736ccf99546ad7d4b7','11efa1b6d4415989635a99b6f3c1a041','8af3f1408fe847affef6cf7596c5cbed']"

   strings:
      $hex_string = { 4141566f2f5a43376371363163306a6b2f73313630302f465245454241434b4c494e4b34552e6769662220626f726465723d223022206865696768743d223135 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
