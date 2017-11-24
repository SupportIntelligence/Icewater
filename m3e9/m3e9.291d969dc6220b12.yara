
rule m3e9_291d969dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.291d969dc6220b12"
     cluster="m3e9.291d969dc6220b12"
     cluster_size="8"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod wapomi"
     md5_hashes="['361d85047d234a186fb85ec3d72cf2f9','4434ef92e2ce3f46757c59ee90401185','c714a7064972c86e625fbe41956fea4c']"

   strings:
      $hex_string = { 496eeab67744ee947f4ba50bc089a1a47ba25e1e6def75a9728a80967e8d97c8f22f25e85ce94174a0d0cf079ad338ff1234e71254355064e4c39c16b12cbbed }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
