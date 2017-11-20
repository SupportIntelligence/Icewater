
rule m2377_58993929c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.58993929c8000b12"
     cluster="m2377.58993929c8000b12"
     cluster_size="9"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['2f845a85186edcdf6fe67740ed47b80d','434651e6ead14b19607c986d1513e0bc','f16e64f945783a219d60fbeb0a6fb186']"

   strings:
      $hex_string = { 8c59e84120c2a15a08836c7a3617a80e9613484a712ef2d5f529a05b87553a2fe2ebc85265b9fab890c49503ed86bbd1bb3c1e1dbf78773cdc2bd6a99b0480f8 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
