
rule n3ed_794416c9cc010b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.794416c9cc010b14"
     cluster="n3ed.794416c9cc010b14"
     cluster_size="11"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bmnup"
     md5_hashes="['1b21623460c27b953b1452110561c42f','225b17b8fa893ab0e584c256bcc1ba04','cd6977c21e3d8c0c7730e5545a833130']"

   strings:
      $hex_string = { 21bb70fc4ef450ec51075324530efa8a5459570ffa10fa9e58ec5bf55c535d11fab75f856020614e653b66656612fa29f9016813fa14fa6b6ae26af86df26d28 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
