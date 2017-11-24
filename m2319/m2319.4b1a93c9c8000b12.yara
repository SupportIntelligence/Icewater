
rule m2319_4b1a93c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.4b1a93c9c8000b12"
     cluster="m2319.4b1a93c9c8000b12"
     cluster_size="6"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker html script"
     md5_hashes="['1bde4fe02a5f365acc618d2380909598','1d48d6845f542e9b17bc55907b3826bb','db1e1830ffaf33196456e90b6bcf9e23']"

   strings:
      $hex_string = { 4141566f2f5a43376371363163306a6b2f73313630302f465245454241434b4c494e4b34552e6769662220626f726465723d223022206865696768743d223135 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
