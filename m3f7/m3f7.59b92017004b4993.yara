
rule m3f7_59b92017004b4993
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.59b92017004b4993"
     cluster="m3f7.59b92017004b4993"
     cluster_size="107"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['03c7e41514d84f45f0ad6e34ff1faba2','043d8e9f45d6a0f868685ff82dc08b99','28ff6fd21a7c1bfb7ad03dff4984e47a']"

   strings:
      $hex_string = { 44394241373030364644343533313338354534313942413941454236453046363238393237373241443834324443464136464330334537343333353130433543 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
