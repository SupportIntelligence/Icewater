
rule m2321_2931940bc6210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.2931940bc6210912"
     cluster="m2321.2931940bc6210912"
     cluster_size="7"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hacktool kmsauto generickd"
     md5_hashes="['0c540291484bdda196b084418a5ef570','0f1f03031b69540ebd1c267620262f63','f65b1b8ad0720942406d6831f707f8ff']"

   strings:
      $hex_string = { 004a662a05a8d94fe1ae27f9ff4ea5fb3a74f43895afaf2382419a29e4ac0bf2089f65877e76fc56ebecc4ede6a9f175fa94aa599c70ce3771b65db8207f473b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
