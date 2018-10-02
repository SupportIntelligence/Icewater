
rule n26bb_399c56d9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.399c56d9c2200b12"
     cluster="n26bb.399c56d9c2200b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="graftor chindo trojandownloader"
     md5_hashes="['ea2bdf3ba8b91b0a10c65542c4349adfe5e309b2','f8d050fe984a42a0f7e296539c8ea6357b86010a','c8f9dd61ef5253c07ec832ec5dc3f1481baf1a61']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.399c56d9c2200b12"

   strings:
      $hex_string = { 72028b0050e8dbfcffff83c40485c075434783c31c3bfe7cdc8b7d108b4f042b0fb893244992f7e903d1c1fa048bf2c1ee1f03f233db3bf37e5b895d08eb068d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
