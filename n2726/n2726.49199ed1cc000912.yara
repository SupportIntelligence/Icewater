
rule n2726_49199ed1cc000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2726.49199ed1cc000912"
     cluster="n2726.49199ed1cc000912"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="symmi malicious dangerousobject"
     md5_hashes="['893688268f6ce62ab9d0a2c9982bbf4ff9f45431','3c2a513cc9013a6890750ba02ab048e607709a6c','5a62d94c6aa07b757146d2baaa7950e54c62fc58']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2726.49199ed1cc000912"

   strings:
      $hex_string = { 98730510eb5ac745ec235300008b5424088d420c8b4ae433c8e83324d9ffb888fa9e7be9f437f9ff90eb3558490e00190f8433feffffeb28a148937ef58bf085 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
