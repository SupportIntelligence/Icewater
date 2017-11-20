
rule m2377_52993929c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.52993929c4000b12"
     cluster="m2377.52993929c4000b12"
     cluster_size="5"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['130c992147f8474a484bb2afbb422fee','21e15824c000387cbda913b4c5fa9377','d1754cff91a778123b01b5712bf51a09']"

   strings:
      $hex_string = { 8c59e84120c2a15a08836c7a3617a80e9613484a712ef2d5f529a05b87553a2fe2ebc85265b9fab890c49503ed86bbd1bb3c1e1dbf78773cdc2bd6a99b0480f8 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
